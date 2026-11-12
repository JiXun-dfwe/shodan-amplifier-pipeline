# -*- coding: utf-8 -*-
"""Shodan 爬虫 + UDP 放大测试 一体化流水线

流程:
1. 循环爬取 Shodan 搜索结果, 每发现新 IP 立刻实测 (masscan + 体积比/吞吐量),
   总放大率 >= MIN_TOTAL_RATIO 的追加进 shodan_kept.json, 不达标的直接丢弃
2. 测完整批后统一写盘 (shodan_kept.json + _tested_cache.json)
3. 已测试过的 IP (无论合格与否) 记录在 _tested_cache.json, 避免重复测试;
   启动时已保留的 IP 也加入缓存, Shodan 再推同样的 IP 不会重测

旧数据清洗只需手动跑一遍, 日常重清洗失效 IP 用 reclean.py

用法: 修改下面【可自定义配置】区, 然后 python shodan_pipeline.py 运行
停止: Ctrl-C (数据每轮都保存, 随时停止都完整)
"""
import json
import os
import random
import re
import socket
import subprocess
import time
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup

import scan_gui               # 复用 measure_ratio / rate_test / PROBE_PAYLOADS / UDP_HDR

# ================【可自定义配置 - 环境变量 SDP_*】================
# 所有参数可用环境变量覆盖, 均有默认值, 不设置即可直接运行。
# PowerShell 示例:  $env:SDP_SEARCH_QUERY="port:1900"; $env:SDP_COOKIE="polito=..."
#
# ---- Shodan 爬虫 ----
# SDP_SEARCH_QUERY    搜索参数, 如 "port:53"、"port:161"、"ssdp"   默认 port:1900
# SDP_MAX_ROUNDS      爬取轮数, 0 = 无限循环 (Ctrl-C 停止)          默认 0
# SDP_POLL_INTERVAL   每轮间隔秒数 "下限,上限" (Shodan 1-2 分钟才刷新) 默认 60,120
# SDP_PAGE_INTERVAL   同一轮内两个 page 之间间隔秒数 "下限,上限"     默认 2,4
# SDP_TIMEOUT         请求超时秒数                                  默认 5
# SDP_COOKIE          Shodan 登录 Cookie (必填, 搜索过滤器需要登录)。
#                     获取: 浏览器登录 shodan.io -> F12 -> 网络 ->
#                     任选请求 -> 复制请求头 Cookie 整段值           默认 空
#
# ---- UDP 测试 ----
# SDP_PORTS           auto = 自动从 SEARCH_QUERY 提取 port:XXXX; 或手填 "1900,123" 默认 auto
# SDP_RATE            masscan 每秒发包速率                          默认 1000
# SDP_RETRIES         masscan 重发次数 (2 = 共发 3 次)              默认 2
# SDP_WAIT            体积比实测每端口等待响应秒数 (SSDP 建议 4-5)   默认 4.0
# SDP_MIN_TOTAL_RATIO 保留阈值: 总放大率达到该倍数才保留             默认 15.0
# SDP_IFACE           本机物理网卡 IP, 留空自动检测 (有 VPN 时手动填) 默认 空
# SDP_RATE_TEST       1/true = 对有响应的端口测回包吞吐量           默认 1
# SDP_RATE_TEST_DURATION 吞吐量测试时长秒数                         默认 3.0
# SDP_RATE_TEST_PPS   吞吐量测试每秒发包数                          默认 50
#
# ---- 文件 ----
# SDP_KEPT_FILE       合格 IP 汇总 (持续累加, 按 best_total_ratio 降序) 默认 shodan_kept.json
# SDP_CACHE_FILE      已测试 IP 缓存 (防重复测试); 删除后会全部重测   默认 _tested_cache.json
#
# ---- 路径 ----
# SDP_MASSCAN         masscan.exe 路径                              默认 masscan/bin/masscan.exe
# ==================================================================

def _env(name, default="", cast=str):
    """读环境变量 SDP_*; 未设置或为空时用默认值"""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    if cast is bool:
        return v.strip().lower() in ("1", "true", "yes", "on")
    try:
        return cast(v)
    except ValueError:
        raise SystemExit("[!] 环境变量 %s 格式错误: %r" % (name, v))


def _env_pair(name, cast=float):
    """解析 '下限,上限' 形式的环境变量 -> 元组"""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return None
    parts = [p.strip() for p in v.split(",")]
    try:
        nums = [cast(p) for p in parts]
    except ValueError:
        raise SystemExit("[!] 环境变量 %s 格式错误: %r (应为 'min,max')" % (name, v))
    return tuple(nums) if len(nums) == 2 else nums[0]


# ---- Shodan 爬虫 ----
SEARCH_QUERY = _env("SDP_SEARCH_QUERY", "port:1900")
MAX_ROUNDS = _env("SDP_MAX_ROUNDS", 0, int)
POLL_INTERVAL = _env_pair("SDP_POLL_INTERVAL") or (60, 120)
PAGE_INTERVAL = _env_pair("SDP_PAGE_INTERVAL") or (2, 4)
TIMEOUT = _env("SDP_TIMEOUT", 5, int)
COOKIE = _env("SDP_COOKIE", "")

# ---- UDP 测试 ----
PORTS = _env("SDP_PORTS", "auto")
RATE = _env("SDP_RATE", "1000")
RETRIES = _env("SDP_RETRIES", 2, int)
WAIT = _env("SDP_WAIT", 4.0, float)
MIN_TOTAL_RATIO = _env("SDP_MIN_TOTAL_RATIO", 15.0, float)
IFACE = _env("SDP_IFACE", "")
RATE_TEST = _env("SDP_RATE_TEST", True, bool)
RATE_TEST_DURATION = _env("SDP_RATE_TEST_DURATION", 3.0, float)
RATE_TEST_PPS = _env("SDP_RATE_TEST_PPS", 50, int)

# ---- 文件 ----
KEPT_FILE = _env("SDP_KEPT_FILE", "shodan_kept.json")
CACHE_FILE = _env("SDP_CACHE_FILE", "_tested_cache.json")
# ==================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
MASSCAN = _env("SDP_MASSCAN", os.path.join(HERE, "masscan", "bin", "masscan.exe"))
BASE_URL = "https://www.shodan.io/search?query={query}&page={page}"
OPEN_RE = re.compile(r"Discovered open port (\S+) on ([\d.]+)")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Referer": "https://www.shodan.io/",
    "Connection": "keep-alive",
}

# 备用解析: 页面结构变化时用正则兜底提取 IP
IP_PATTERN = re.compile(r'href="/host/(\d{1,3}(?:\.\d{1,3}){3})"[^>]*class="title text-dark"')
ANY_HOST_PATTERN = re.compile(r'href="/host/(\d{1,3}(?:\.\d{1,3}){3})"')

def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def p(name):
    return os.path.join(HERE, name)


# ---------- masscan 扫描与实测 (原 batch_scan.py) ----------
def detect_lan_ip():
    """探测本机网卡 IP, 自动排除 TUN(198.18.x)/回环/链路本地地址"""
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
    seen, ok, tun = set(), [], None
    for ip in cands:
        if ip in seen:
            continue
        seen.add(ip)
        if ip.startswith(("127.", "169.254.", "198.18.")):
            tun = ip if ip.startswith("198.18.") else tun
        else:
            ok.append(ip)
    return (ok[0] if ok else None), tun


def masscan_sweep(ips, ports_arg, rate, retries, iface):
    """masscan UDP 扫描, 返回 {(ip, port)} 开放集合"""
    out_file = os.path.join(HERE, "_sweep_result.json")
    udp_ports = ",".join("U:%s" % x for x in ports_arg.split(","))
    cmd = [MASSCAN, *ips, "-p", udp_ports, "--banners",
           "--rate", str(rate), "--retries", str(retries), "-oJ", out_file]
    if iface:  # 仅在用户显式指定时传, 留空让 masscan 自动选择更可靠
        cmd += ["--interface", iface]
    log("masscan 开始: %d 个 IP × %d 个端口, rate=%s" %
        (len(ips), len(ports_arg.split(",")), rate))
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    tail = "\n".join((r.stdout or "").splitlines()[-3:])
    log("masscan 输出尾部:\n" + tail)
    opens = set()
    try:
        raw = open(out_file, encoding="utf-8").read()
        raw = re.sub(r",\s*([\]}])", r"\1", raw)  # 修复 masscan JSON 尾逗号
        # strict=False: masscan banner 里可能含原始控制字符(SSDP 换行等)
        for rec in json.loads(raw, strict=False) or []:
            for port in rec.get("ports", []):
                if port.get("proto") == "udp":
                    opens.add((rec["ip"], port["port"]))
    except (OSError, ValueError) as e:
        log("解析 masscan 结果失败: %s" % e)
    finally:
        try:
            os.remove(out_file)
        except OSError:
            pass
    return opens


def measure_all(opens, wait, bind_ip):
    """逐个实测体积比 + 吞吐量, 端口间留间隔避免速率限制"""
    results = {}  # ip -> [port_result]
    pairs = sorted(opens)
    for i, (ip, port) in enumerate(pairs):
        if i:
            time.sleep(1.5)
        r = scan_gui.measure_ratio(ip, port, wait=wait, bind_ip=bind_ip)
        log("  %s:%d -> %s" % (ip, port,
            ("收到 %d 包" % len(r["sizes"])) if r["sizes"] else "无响应"))
        if r["sizes"] and RATE_TEST:
            rt = scan_gui.rate_test(ip, port, RATE_TEST_DURATION,
                                    RATE_TEST_PPS, bind_ip)
            r["rate_test"] = rt
            log("    回包速率: %s 包/秒, %s 字节/秒 (发了 %d 个请求)"
                % (rt["resp_pps"], rt["resp_bytes_per_sec"], rt["sent_requests"]))
        results.setdefault(ip, []).append(r)
    return results


# ---------- Shodan 页面爬取 (来自 shodan_scraper.py) ----------
def is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def parse_ips(html: str) -> list:
    """优先 BeautifulSoup 解析 title text-dark 元素, 失败则正则兜底"""
    ips = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.select("a.title.text-dark"):
            m = re.match(r"^/host/(\d{1,3}(?:\.\d{1,3}){3})$", a.get("href", ""))
            if m and is_valid_ipv4(m.group(1)):
                ips.append(m.group(1))
    except Exception:
        pass
    if not ips:
        ips = [ip for ip in IP_PATTERN.findall(html) if is_valid_ipv4(ip)]
    if not ips:
        for ip in ANY_HOST_PATTERN.findall(html):
            if is_valid_ipv4(ip) and ip not in ips:
                ips.append(ip)
    return ips


def fetch_page(query: str, page: int):
    """每次请求都新建独立会话: 复用 Session 会让 Shodan 连续返回相同结果"""
    url = BASE_URL.format(query=quote(query), page=page)
    session = requests.Session()
    if COOKIE.strip():
        session.headers["Cookie"] = COOKIE.strip()
    try:
        resp = session.get(url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200:
            if "Please log in to use search filters" in resp.text:
                log("[!] Shodan 要求登录: 请在配置区 COOKIE 填入浏览器 Cookie")
                return None
            return resp.text
        log("[!] HTTP %s @ page=%s" % (resp.status_code, page))
    except requests.RequestException as e:
        log("[!] 请求失败 @ page=%s: %s" % (page, e))
    return None


# ---------- 结果存储 ----------
def load_kept(path):
    try:
        data = json.load(open(path, encoding="utf-8"))
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict) and "ip" in r]
    except (OSError, ValueError):
        pass
    return []


def save_kept(kept, path):
    kept.sort(key=lambda x: x.get("best_total_ratio", 0), reverse=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(kept, f, ensure_ascii=False, indent=2)


def load_cache(path):
    try:
        data = json.load(open(path, encoding="utf-8"))
        if isinstance(data, dict):
            return set(data.get("ips", []))
        if isinstance(data, list):
            return set(data)
    except (OSError, ValueError):
        pass
    return set()


def save_cache(cache, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"ips": sorted(cache)}, f, indent=2)


# ---------- 测试与分类 ----------
def resolve_ports():
    if str(PORTS).strip().lower() == "auto":
        m = re.search(r"port:(\d+)", SEARCH_QUERY)
        return m.group(1) if m else "1900"
    return str(PORTS).strip()


def classify(results, ips):
    """按总放大率阈值分类 -> (合格记录列表, 不合格 ip 列表)"""
    qualified, bad = [], []
    for ip in ips:
        ports_out, best = [], 0.0
        for r in results.get(ip) or []:
            if not r["sizes"]:
                continue
            mx = max(r["sizes"]) + scan_gui.UDP_HDR
            tot = sum(r["sizes"]) + scan_gui.UDP_HDR * len(r["sizes"])
            best = max(best, tot / r["req"])
            entry = {
                "port": r["port"], "req_bytes": r["req"],
                "packets": len(r["sizes"]), "sizes": r["sizes"],
                "single_max_bytes": mx,
                "single_ratio": round(mx / r["req"], 2),
                "total_bytes": tot,
                "total_ratio": round(tot / r["req"], 2),
            }
            if r.get("rate_test"):
                entry["rate_test"] = r["rate_test"]
            ports_out.append(entry)
        if ports_out and best >= MIN_TOTAL_RATIO:
            ports_out.sort(key=lambda x: x["total_ratio"], reverse=True)
            qualified.append({"ip": ip, "best_total_ratio": round(best, 2),
                              "ports": ports_out})
        else:
            bad.append(ip)
    return qualified, bad


def merge_kept(kept, qualified):
    """合并合格记录; 同 IP 已存在时仅在新放大率更高时更新, 返回新增的记录"""
    by_ip = {r["ip"]: i for i, r in enumerate(kept)}
    added = []
    for rec in qualified:
        if rec["ip"] in by_ip:
            i = by_ip[rec["ip"]]
            if rec["best_total_ratio"] > kept[i].get("best_total_ratio", 0):
                kept[i] = rec
                added.append(rec)
        else:
            kept.append(rec)
            by_ip[rec["ip"]] = len(kept) - 1
            added.append(rec)
    return added


def test_ips(ips, ports, iface, kept, cache):
    """对一批 IP 完整测试: masscan 扫描 -> 逐 IP 实测 -> 分类合并
    测完整批后统一写盘
    """
    log("开始测试 %d 个 IP (端口 %s)..." % (len(ips), ports))
    opens = masscan_sweep(ips, ports, RATE, RETRIES, IFACE or None)
    log("masscan 发现 %d 个开放 (ip,port) 对" % len(opens))
    opens_by_ip = {}
    for ip, port in opens:
        opens_by_ip.setdefault(ip, []).append(port)

    n_qual = n_added = n_drop = measured = 0
    for i, ip in enumerate(ips):
        results = {}
        pairs = {(ip, p) for p in opens_by_ip.get(ip, [])}
        if pairs:
            if measured:  # 端口间留间隔, 避免 UDP 服务速率限制(ntpd 等)
                time.sleep(1.5)
            measured += 1
            results = measure_all(pairs, WAIT, iface)
        qualified, bad = classify(results, [ip])
        added = merge_kept(kept, qualified)
        if qualified:
            n_qual += 1
            n_added += len(added)
            for rec in added:
                port = rec["ports"][0]
                extra = ""
                if port.get("rate_test"):
                    extra = ", 回包 %s 包/秒" % port["rate_test"]["resp_pps"]
                log("  [+] %s %d/udp 单包 %.2fx 总 %.2fx (%d包%s)"
                    % (rec["ip"], port["port"], port["single_ratio"],
                       port["total_ratio"], port["packets"], extra))
        else:
            n_drop += 1
        cache.add(ip)
        log("  进度 %d/%d: %s -> %s"
            % (i + 1, len(ips), ip, "保留" if qualified else "清洗丢弃"))
    # 整批测完统一写盘
    save_kept(kept, p(KEPT_FILE))
    save_cache(cache, p(CACHE_FILE))
    log("测试完成: 共 %d 个, 保留 %d (新增记录 %d 条), 清洗丢弃 %d, 已写盘"
        % (len(ips), n_qual, n_added, n_drop))


def main():
    kept = load_kept(p(KEPT_FILE))
    cache = load_cache(p(CACHE_FILE))
    cache.update(r["ip"] for r in kept)  # 已合格的也不再重测

    ports = resolve_ports()
    iface, tun = (IFACE, None) if IFACE else detect_lan_ip()
    if tun and not iface:
        log("警告: 检测到 VPN/TUN(%s) 且未找到物理网卡 IP, 建议配置区 IFACE 手动填" % tun)
    log("网卡 IP: %s | 端口: %s | 阈值: 总放大率 >= %.1fx | 吞吐量测试: %s"
        % (iface or "自动", ports, MIN_TOTAL_RATIO, "开" if RATE_TEST else "关"))
    log("当前已保留 %d 个合格 IP, 已测试 %d 个"
        % (len(kept), len(cache)))

    log("开始爬取 Shodan, 查询: %s%s" %
        (SEARCH_QUERY, " (无限循环)" if not MAX_ROUNDS else " (最多 %d 轮)" % MAX_ROUNDS))
    rnd = 0
    try:
        while True:
            rnd += 1
            if MAX_ROUNDS and rnd > MAX_ROUNDS:
                break
            # 每轮开始重新读盘: 让 reclean --filter 等外部修改在本轮生效
            disk_kept = load_kept(p(KEPT_FILE))
            disk_cache = load_cache(p(CACHE_FILE))
            if len(disk_kept) != len(kept) or len(disk_cache) != len(cache):
                log("检测到外部修改, 重新载入: 保留 %d 个, 已测试 %d 个"
                    % (len(disk_kept), len(disk_cache)))
            kept, cache = disk_kept, disk_cache
            cache.update(r["ip"] for r in kept)
            round_ips = []
            for page in (1, 2):
                html = fetch_page(SEARCH_QUERY, page)
                if html:
                    round_ips.extend(parse_ips(html))
                if page == 1:
                    time.sleep(random.uniform(*PAGE_INTERVAL))
            new = [ip for ip in dict.fromkeys(round_ips) if ip not in cache]
            log("第 %d 轮: 页面返回 %d 个 IP, 其中新 %d 个"
                % (rnd, len(set(round_ips)), len(new)))
            if new:
                test_ips(new, ports, iface, kept, cache)
            if MAX_ROUNDS and rnd >= MAX_ROUNDS:
                break
            wait = random.uniform(*POLL_INTERVAL)
            log("等待 %.0f 秒后开始下一轮 (Ctrl-C 停止)..." % wait)
            time.sleep(wait)
    except KeyboardInterrupt:
        log("已手动停止, 数据已保存")
    save_kept(kept, p(KEPT_FILE))
    save_cache(cache, p(CACHE_FILE))
    log("完成! 共保留 %d 个合格 IP -> %s" % (len(kept), KEPT_FILE))


if __name__ == "__main__":
    main()
