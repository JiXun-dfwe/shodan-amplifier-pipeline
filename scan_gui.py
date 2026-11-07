# -*- coding: utf-8 -*-
"""masscan 可视化扫描工具
用法: python scan_gui.py
依赖: tkinter(内置), D:\\masscan\\masscan\\bin\\masscan.exe
"""
import os
import queue
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

MASSCAN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "masscan", "bin", "masscan.exe")

OPEN_RE = re.compile(r"Discovered open port (\S+)")
BANNER_RE = re.compile(r"banner: (\S+)")


def build_ports(raw: str, proto: str) -> str:
    """把用户输入 '5060,53' / '1-1000' 转成 'U:5060,U:53' 形式"""
    segments = [s.strip() for s in raw.replace("，", ",").split(",") if s.strip()]
    p = "U" if proto == "UDP" else "T"
    return ",".join(f"{p}:{s}" for s in segments)


def parse_port_list(raw: str, cap: int = 25) -> list:
    """'5060,53,100-103' -> [5060,53,100,101,102,103]，超出 cap 截断"""
    ports = []
    for seg in raw.replace("，", ",").split(","):
        seg = seg.strip()
        if not seg:
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", seg)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            ports.extend(range(lo, min(hi, lo + cap - 1) + 1))
        elif seg.isdigit():
            ports.append(int(seg))
    return ports[:cap]


# 与 masscan templ-payloads.c 完全一致的 UDP 探测载荷（用于体积比实测）
UDP_HDR = 20 + 8  # IP 20 + UDP 8
PROBE_PAYLOADS = {
    7:    b"masscan-test 0x00000000",            # Echo
    17:   b"masscan-test",                       # QOTD
    19:   b"masscan-test",                       # chargen
    53:   b"\x50\xb6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x07version\x04bind\x00\x00\x10\x00\x03",           # DNS CHAOS
    69:   b"\x00\x01masscan-test\x00netascii\x00",              # TFTP RRQ
    111:  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
          b"\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x00"
          b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # portmapper
    123:  (b"\x1b" + b"\x00" * 47,                        # NTPv3 客户端时间查询
          b"\x17\x00\x03\x2a" + b"\x00" * 44),            # monlist(测放大率用)
    137:  b"\xab\x12\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
          b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",  # NBSTAT
    161:  b"\x30\x39\x02\x01\x00\x04\x06public\xa0\x2c"
          b"\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
          b"\x30\x1e\x30\x0d\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x01\x00"
          b"\x05\x00\x30\x0d\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x05\x00"
          b"\x05\x00",                                          # SNMP GET
    5060: b"OPTIONS sip:carol@chicago.com SIP/2.0\r\n"
          b"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n"
          b"Max-Forwards: 70\r\n"
          b"To: <sip:carol@chicago.com>\r\n"
          b"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
          b"Call-ID: a84b4c76e66710\r\n"
          b"CSeq: 63104 OPTIONS\r\n"
          b"Contact: <sip:alice@pc33.atlanta.com>\r\n"
          b"Accept: application/sdp\r\n"
          b"Content-Length: 0\r\n",                             # SIP OPTIONS
    5683: b"\x40\x01\x01\xce\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b"
          b"\x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65",              # CoAP GET
    11211: b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",        # memcached
    1900: b"M-SEARCH * HTTP/1.1\r\n"
          b"HOST: 239.255.255.250:1900\r\n"
          b"MAN: \"ssdp:discover\"\r\n"
          b"MX: 1\r\n"
          b"ST: ssdp:all\r\n",                                  # SSDP
}


def measure_ratio(ip: str, port: int, wait: float = 3.0,
                  bind_ip: str = None) -> dict:
    """对单端口发 UDP 探测，实测请求/响应字节数。
    返回 {port, req, sizes:[响应载荷字节数...], err}
    bind_ip: 绑定本机网卡 IP, 可绕过 VPN/代理 TUN 截流
    载荷可以是 bytes 或多个 bytes 组成的元组(依次尝试直到有响应)
    """
    plist = PROBE_PAYLOADS.get(port, b"")
    if isinstance(plist, (bytes, bytearray)):
        plist = (bytes(plist),)
    sizes = []
    err = None
    req = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    for payload in plist:
        req = UDP_HDR + len(payload)
        deadline = time.time() + wait
        sizes = []
        try:
            if bind_ip:
                sock.bind((bind_ip, 0))
            sock.connect((ip, port))
            sock.send(payload)
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(65535)
                    sizes.append(len(data))
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break  # Windows: 收到 ICMP port unreachable = 端口关闭
        except OSError as e:
            err = str(e)
        if sizes:
            break  # 该载荷有效
    sock.close()
    return {"port": port, "req": req, "sizes": sizes, "err": err}


def detect_lan_ip() -> str:
    """探测本机物理网卡 IP, 排除回环/链路本地/VPN TUN(198.18.x), 失败返回空"""
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
    for ip in dict.fromkeys(cands):
        if not ip.startswith(("127.", "169.254.", "198.18.")):
            return ip
    return ""


# ---------- 吞吐量测试 ----------
RATE_TEST_DURATION = 3.0   # 每端口测试时长(秒)
RATE_TEST_PPS = 50         # 每秒发出的请求数


def rate_test(ip: str, port: int, duration: float = RATE_TEST_DURATION,
              send_pps: int = RATE_TEST_PPS, bind_ip: str = None) -> dict:
    """以 send_pps 速率持续发包 duration 秒, 统计目标的回包速率(包/秒, 字节/秒)"""
    payload = PROBE_PAYLOADS.get(port, b"")
    if isinstance(payload, (tuple, list)):
        payload = payload[0]
    interval = 1.0 / send_pps
    sent = recv_n = recv_bytes = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    try:
        if bind_ip:
            sock.bind((bind_ip, 0))
        sock.connect((ip, port))
        start = time.time()
        send_until = start + duration
        next_send, end = start, start + duration + 1.0
        while time.time() < end:
            now = time.time()
            if now >= next_send and next_send <= send_until:
                try:
                    sock.send(payload)
                    sent += 1
                except OSError:
                    pass
                next_send += interval
            try:
                data, _ = sock.recvfrom(65535)
                recv_n += 1
                recv_bytes += len(data)
            except socket.timeout:
                continue
            except ConnectionResetError:
                break
    except OSError:
        pass
    finally:
        sock.close()
    total_bytes = recv_bytes + UDP_HDR * recv_n
    return {
        "sent_requests": sent,
        "resp_packets": recv_n,
        "resp_bytes": total_bytes,
        "resp_pps": round(recv_n / duration, 1),
        "resp_bytes_per_sec": int(total_bytes / duration),
    }


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.proc = None
        self.q = queue.Queue()
        root.title("masscan 扫描工具 (默认 UDP 模式)")
        root.resizable(True, True)
        self._build_form()
        self._build_output()
        self.root.after(100, self._poll_output)

    # ---------- 界面 ----------
    def _build_form(self):
        f = ttk.Frame(self.root, padding=10)
        f.pack(fill="x")

        self.var_ip = tk.StringVar()
        self.var_ports = tk.StringVar(value="5060")
        self.var_proto = tk.StringVar(value="UDP")       # 默认 UDP
        self.var_rate = tk.StringVar(value="100")
        self.var_retry = tk.StringVar(value="2")
        self.var_iface = tk.StringVar(value="")          # 可选, 留空自动绑定本机 IP

        rows = [
            ("目标 IP / 网段:", self.var_ip, "例如 192.168.1.1 或 192.168.1.0/24"),
            ("端口:", self.var_ports, "支持 5060 或 5060,53 或 1-1000"),
            ("扫描模式:", None, ""),
            ("速率(包/秒):", self.var_rate, "默认 100"),
            ("重试次数:", self.var_retry, "0=每个探测只发一次"),
            ("网卡(可选):", self.var_iface, "留空=自动绑定本机 IP 绕过 VPN; 也可手动填如 192.168.1.8"),
        ]
        for i, (label, var, tip) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="e", pady=3)
            if var is self.var_proto:
                box = ttk.Combobox(f, textvariable=self.var_proto,
                                   values=["UDP", "TCP"], state="readonly", width=28)
                box.grid(row=i, column=1, sticky="w", pady=3)
            else:
                e = ttk.Entry(f, textvariable=var, width=30)
                e.grid(row=i, column=1, sticky="w", pady=3)
            if tip:
                ttk.Label(f, text=tip, foreground="gray").grid(
                    row=i, column=2, sticky="w", padx=6)

        btns = ttk.Frame(f)
        btns.grid(row=len(rows), column=1, sticky="w", pady=8)
        self.btn_scan = ttk.Button(btns, text="开始扫描", command=self.start)
        self.btn_scan.pack(side="left", padx=(0, 6))
        self.btn_ratio = ttk.Button(btns, text="测体积比", command=self.run_ratio)
        self.btn_ratio.pack(side="left", padx=(0, 6))
        self.btn_rate = ttk.Button(btns, text="测吞吐量", command=self.run_rate)
        self.btn_rate.pack(side="left", padx=(0, 6))
        self.btn_stop = ttk.Button(btns, text="停止", command=self.stop,
                                   state="disabled")
        self.btn_stop.pack(side="left")

    def _build_output(self):
        f = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="输出:").pack(anchor="w")
        self.txt = tk.Text(f, height=18, width=90, font=("Consolas", 9),
                           bg="#111", fg="#ddd")
        self.txt.pack(fill="both", expand=True)
        self.txt.tag_config("open", foreground="#4fc3f7",
                            font=("Consolas", 9, "bold"))
        self.txt.tag_config("banner", foreground="#ffd54f")

    # ---------- 扫描 ----------
    def start(self):
        ip = self.var_ip.get().strip()
        if not ip:
            messagebox.showwarning("提示", "请填写目标 IP")
            return
        if not os.path.isfile(MASSCAN):
            messagebox.showerror("错误", f"找不到 masscan.exe:\n{MASSCAN}")
            return
        try:
            args = [MASSCAN, ip,
                    "-p", build_ports(self.var_ports.get(), self.var_proto.get()),
                    "--rate", str(int(self.var_rate.get())),
                    "--retries", str(int(self.var_retry.get())),
                    "--banners"]
            iface = self.var_iface.get().strip()
            if iface:
                args += ["--interface", iface]
        except ValueError:
            messagebox.showerror("错误", "速率/重试必须是数字")
            return

        self.txt.delete("1.0", "end")
        self._log(f"$ {' '.join(args)}\n\n")
        self.btn_scan.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        threading.Thread(target=self._reader, daemon=True).start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self._log("\n[已手动停止]\n")

    def _reader(self):
        for line in self.proc.stdout:
            self.q.put(line.decode("utf-8", errors="replace"))
        self.q.put(None)

    def _poll_output(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item is None:
                    self._summary()
                    self.btn_scan.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    break
                if isinstance(item, tuple):   # 后台线程的输出
                    if item[0] == "ratio_done":
                        self.btn_ratio.config(state="normal")
                    elif item[0] == "rate_done":
                        self.btn_rate.config(state="normal")
                    else:
                        self._log(item[1])
                    continue
                self._log(item, highlight=True)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_output)

    # ---------- 体积比测量 ----------
    def run_ratio(self, auto_ports=None):
        ip = self.var_ip.get().strip()
        if not ip:
            messagebox.showwarning("提示", "请填写目标 IP")
            return
        # 网卡栏填了本机 IP 就用它; 留空则自动探测本机物理网卡 IP (绕过 VPN/代理 TUN)
        iface = self.var_iface.get().strip()
        if iface and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", iface):
            bind_ip = iface
        else:
            bind_ip = detect_lan_ip()
        if auto_ports:
            ports = auto_ports  # 扫描发现的开放 UDP 端口
        else:
            ports = parse_port_list(self.var_ports.get())
        if not ports:
            messagebox.showwarning("提示", "端口格式无法识别")
            return
        if len(ports) > 20:
            self.q.put(("ratio", f"[体积比] 端口数过多, 仅测前 20 个\n"))
            ports = ports[:20]
        self.btn_ratio.config(state="disabled")
        self.q.put(("ratio",
                    f"\n--- UDP 请求/响应体积比 ({ip}, 源 {bind_ip or '默认'}) ---\n"))
        threading.Thread(target=self._ratio_worker,
                         args=(ip, ports, bind_ip), daemon=True).start()

    def _ratio_worker(self, ip, ports, bind_ip):
        for i, p in enumerate(ports):
            if i:  # 端口之间留间隔, 避免 UDP 服务速率限制(ntpd 默认丢弃超频源)
                time.sleep(1.5)
            r = measure_ratio(ip, p, bind_ip=bind_ip)
            if r["err"]:
                line = f"端口 {r['port']}/udp: 出错 ({r['err']})\n"
            elif not r["sizes"]:
                line = (f"端口 {r['port']}/udp: 请求 {r['req']}B"
                        f" (载荷{r['req']-UDP_HDR}B) -> 无响应\n")
            else:
                mx = max(r["sizes"])
                resp = mx + UDP_HDR
                ratio = resp / r["req"]
                # 多包响应: 总放大率 = 所有响应字节之和 / 请求字节
                tot = sum(r["sizes"]) + UDP_HDR * len(r["sizes"])
                tratio = tot / r["req"]
                line = (f"端口 {r['port']}/udp: 请求 {r['req']}B"
                        f" (载荷{r['req']-UDP_HDR}B) -> 收到 {len(r['sizes'])} 包,"
                        f" 单包最大 {resp}B (载荷{mx}B)"
                        f"  单包比率 {ratio:.2f}x, 总放大率 {tratio:.2f}x"
                        f"{'  ⚠ 可疑反射源' if max(ratio, tratio) > 10 else ''}\n")
            self.q.put(("ratio", line))
        self.q.put(("ratio", "--- 测量完成 ---\n"))
        self.q.put(("ratio_done", None))

    # ---------- 吞吐量测试 ----------
    def run_rate(self, auto_ports=None):
        ip = self.var_ip.get().strip()
        if not ip:
            messagebox.showwarning("提示", "请填写目标 IP")
            return
        iface = self.var_iface.get().strip()
        if iface and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", iface):
            bind_ip = iface
        else:
            bind_ip = detect_lan_ip()
        if auto_ports:
            ports = auto_ports
        else:
            ports = parse_port_list(self.var_ports.get())
        if not ports:
            messagebox.showwarning("提示", "端口格式无法识别")
            return
        if len(ports) > 10:
            self.q.put(("rate", f"[吞吐量] 端口数过多, 仅测前 10 个\n"))
            ports = ports[:10]
        self.btn_rate.config(state="disabled")
        self.q.put(("rate",
                    f"\n--- UDP 回包吞吐量测试 ({ip}, 源 {bind_ip or '默认'},"
                    f" 每端口 {RATE_TEST_DURATION:.0f}s @{RATE_TEST_PPS}包/秒) ---\n"))
        threading.Thread(target=self._rate_worker,
                         args=(ip, ports, bind_ip), daemon=True).start()

    def _rate_worker(self, ip, ports, bind_ip):
        for i, p in enumerate(ports):
            if i:
                time.sleep(1.5)  # 端口间隔, 避免触发服务端速率限制
            r = rate_test(ip, p, bind_ip=bind_ip)
            if not r["sent_requests"]:
                line = f"端口 {p}/udp: 无法发送 ({r['resp_packets']} 包)\n"
            elif not r["resp_packets"]:
                line = (f"端口 {p}/udp: 发了 {r['sent_requests']} 个请求"
                        f" -> 无回包 (0 包/秒)\n")
            else:
                line = (f"端口 {p}/udp: 发 {r['sent_requests']} 请求 -> "
                        f"回 {r['resp_packets']} 包 / {r['resp_bytes']}B,"
                        f" 回包速率 {r['resp_pps']} 包/秒,"
                        f" 吞吐 {r['resp_bytes_per_sec']:,} 字节/秒\n")
            self.q.put(("rate", line))
        self.q.put(("rate", "--- 吞吐量测试完成 ---\n"))
        self.q.put(("rate_done", None))

    def _log(self, text, highlight=False):
        self.txt.insert("end", text)
        self.txt.see("end")
        if not highlight:
            return
        m = OPEN_RE.search(text)
        if m:
            self.txt.tag_add("open", f"end-{len(text)+1}c", "end-1c")
        elif BANNER_RE.search(text):
            self.txt.tag_add("banner", f"end-{len(text)+1}c", "end-1c")

    def _summary(self):
        content = self.txt.get("1.0", "end")
        opens = OPEN_RE.findall(content)
        self._log("\n" + "=" * 50 + "\n")
        udp_opens = [o for o in opens if o.endswith("/udp")]
        if opens:
            self._log(f"扫描完成: 发现 {len(opens)} 个开放端口\n")
            for o in opens:
                self._log(f"  OPEN  {o}\n")
        else:
            self._log("扫描完成: 未发现开放端口 (无响应)\n")
        # UDP 扫描发现开放端口时, 自动测量体积比
        if udp_opens and self.var_proto.get() == "UDP":
            ports = sorted({int(o.split("/")[0]) for o in udp_opens})
            self.run_ratio(auto_ports=ports)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
