# -*- coding: utf-8 -*-
"""重清洗: 把 shodan_kept.json 里失效 / 放大率不足的 IP 清洗出去

三种模式:
1. 全量重测 (默认, 不带参数): python reclean.py
   分两阶段: 先 masscan 探测所有 IP 是否回包, 无响应的直接清洗;
   再对有回包的按其记录的端口实测放大倍率/吞吐量:
   - 仍达标 -> 更新记录(新的体积比/吞吐量)
   - 不达标 -> 从 kept.json 清除, 并从 _tested_cache.json 移除
     (之后 Shodan 再爬到它时流水线会重新测试, 恢复了可再次收录)
2. 轻量清洗 (不发任何包): python reclean.py --filter [倍数]
   只按已记录的总放大率过滤, 低于阈值的 IP 直接清除。
   适合快速清理, 但发现不了"记录达标但实际已失效"的 IP
3. 无响应清洗 (只探测回包, 不测放大倍率): python reclean.py --dead
   masscan 探测每个 IP 记录的端口, 无任何回包的 IP 直接清除;
   有回包的 IP 原样保留 (不重测放大率/吞吐量)

命令行参数:
  --filter [倍数]   轻量清洗模式; 倍数省略时用 shodan_pipeline.py 的 MIN_TOTAL_RATIO
  --dead            无响应清洗模式; 只探测回包, 不测放大倍率

注意: 全量重测模式运行前请勿同时运行 shodan_pipeline.py (会抢 masscan 临时文件)
每次清洗启动时会先把 shodan_kept.json / _tested_cache.json 备份为 *.bak
(每次覆盖上一次备份), 清洗出错可用备份直接还原
"""
import argparse
import os
import shutil

import shodan_pipeline as sp
import github_sync        # 清洗完成后自动把 shodan_kept.json 推送 GitHub

# ================【可自定义配置 - 环境变量 RC_*】================
# 所有参数可用环境变量覆盖, 均有默认值, 不设置即可直接运行。
# PowerShell 示例:  $env:RC_MIN_TOTAL_RATIO="15"
#
# RC_MIN_TOTAL_RATIO  全量重测模式的阈值; 不设 = 沿用 shodan_pipeline.py 的
#                     SDP_MIN_TOTAL_RATIO (也可单独填如 15.0, 对旧 IP 更严格)
# RC_MAX_DEAD_RATIO   断网保护: 探测后无响应 IP 超过总数该比例 (大概率本机
#                     断网而非服务全挂), 中止清洗且不写盘。设为 1 关闭保护  默认 0.7
# ==================================================================

def _env(name, default="", cast=str):
    """读环境变量 RC_*; 未设置或为空时用默认值"""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    try:
        return cast(v)
    except ValueError:
        raise SystemExit("[!] 环境变量 %s 格式错误: %r" % (name, v))


MIN_TOTAL_RATIO = _env("RC_MIN_TOTAL_RATIO", None, float)
MAX_DEAD_RATIO = _env("RC_MAX_DEAD_RATIO", 0.7, float)
# ==================================================================

log = sp.log


def backup_files():
    """清洗启动前备份 ip 文件到 output/ 目录, 每次运行覆盖上一次备份"""
    out_dir = os.path.join(sp.HERE, "output")
    os.makedirs(out_dir, exist_ok=True)
    for fname in (sp.KEPT_FILE, sp.CACHE_FILE):
        src = sp.p(fname)
        dst = os.path.join(out_dir, fname + ".bak")
        try:
            if os.path.exists(src):
                shutil.copyfile(src, dst)
                log("已备份 %s -> output/%s.bak" % (fname, fname))
        except OSError as e:
            log("[!] 备份 %s 失败: %s (继续清洗)" % (fname, e))


def light_filter(threshold):
    """轻量清洗: 不发包, 只按已记录的 best_total_ratio 过滤"""
    kept = sp.load_kept(sp.p(sp.KEPT_FILE))
    if not kept:
        log("shodan_kept.json 为空或不存在, 无需清洗")
        return
    cache = sp.load_cache(sp.p(sp.CACHE_FILE))
    log("轻量清洗: 阈值 总放大率 >= %.2fx, 当前 %d 个 IP"
        % (threshold, len(kept)))
    kept_out, removed = [], []
    for rec in kept:
        if rec.get("best_total_ratio", 0) >= threshold:
            kept_out.append(rec)
        else:
            removed.append((rec["ip"], rec.get("best_total_ratio", 0)))
            cache.discard(rec["ip"])  # 从缓存移除, Shodan 再爬到会重新测试
    sp.save_kept(kept_out, sp.p(sp.KEPT_FILE))
    sp.save_cache(cache, sp.p(sp.CACHE_FILE))
    log("轻量清洗完成: 保留 %d, 清除 %d, 已写盘" % (len(kept_out), len(removed)))
    for ip, ratio in sorted(removed, key=lambda x: x[1]):
        log("  [-] %s (总放大率 %.2fx < %.2fx)" % (ip, ratio, threshold))


def group_by_ports(kept):
    """按记录里的端口分组: (端口元组) -> [ip, ...], 同组一次性 masscan 扫完"""
    groups = {}
    for rec in kept:
        ports = tuple(sorted({int(x["port"]) for x in rec.get("ports", [])
                              if isinstance(x, dict) and "port" in x}))
        groups.setdefault(ports, []).append(rec["ip"])
    return groups


def mass_dead_guard(ips, alive):
    """断网保护: 无响应比例过高时中止清洗(不写盘), 返回 True 表示已中止"""
    dead = len(ips) - len(alive & set(ips))
    if dead > len(ips) * MAX_DEAD_RATIO:
        log("=" * 50)
        log("[!] 断网保护触发: %d 个 IP 中 %d 个无响应 (超过 %.0f%%), "
            "大概率是本机网络故障而非服务全部失效"
            % (len(ips), dead, MAX_DEAD_RATIO * 100))
        log("本次清洗已中止, shodan_kept.json / _tested_cache.json 未修改; "
            "请检查网络后重跑")
        return True
    return False


def prune_dead():
    """无响应清洗: masscan 探测回包, 无回包的直接清除, 不测放大倍率"""
    kept = sp.load_kept(sp.p(sp.KEPT_FILE))
    if not kept:
        log("shodan_kept.json 为空或不存在, 无需清洗")
        return
    cache = sp.load_cache(sp.p(sp.CACHE_FILE))

    iface, tun = (sp.IFACE, None) if sp.IFACE else sp.detect_lan_ip()
    if tun and not iface:
        log("警告: 检测到 VPN/TUN(%s) 且未找到物理网卡 IP, 建议在 shodan_pipeline.py "
            "的 IFACE 里手动填本机 IP" % tun)
    log("无响应清洗: %d 个已保留 IP | 网卡: %s (只探测回包, 不测放大倍率)"
        % (len(kept), iface or "自动"))

    alive = set()
    for ports, ips in sorted(group_by_ports(kept).items()):
        ports_arg = ",".join(str(x) for x in ports)
        log("--- 探测 %d 个 IP (端口 %s) ---" % (len(ips), ports_arg))
        opens = sp.masscan_sweep(ips, ports_arg, sp.RATE, sp.RETRIES,
                                 sp.IFACE or None)
        alive |= {ip for ip, _port in opens}
        log("该组: 有回包 %d, 无回包 %d"
            % (len(alive & set(ips)), len(set(ips) - alive)))
    if mass_dead_guard({rec["ip"] for rec in kept}, alive):
        return

    kept_out, removed = [], []
    for rec in kept:
        if rec["ip"] in alive:
            kept_out.append(rec)
        else:
            removed.append(rec["ip"])
            cache.discard(rec["ip"])  # 从缓存移除, Shodan 再爬到会重新测试
    sp.save_kept(kept_out, sp.p(sp.KEPT_FILE))
    sp.save_cache(cache, sp.p(sp.CACHE_FILE))
    log("无响应清洗完成: 保留 %d, 清除 %d, 已写盘"
        % (len(kept_out), len(removed)))
    for ip in sorted(removed):
        log("  [-] %s 清洗 (无响应, 从缓存移除, Shodan 再爬到会重新测试)" % ip)


def full_reclean():
    """全量重测: 每个重新实测, 不达标的清除"""
    threshold = MIN_TOTAL_RATIO if MIN_TOTAL_RATIO is not None else sp.MIN_TOTAL_RATIO
    sp.MIN_TOTAL_RATIO = threshold  # 让 sp.classify 使用该阈值

    kept = sp.load_kept(sp.p(sp.KEPT_FILE))
    if not kept:
        log("shodan_kept.json 为空或不存在, 无需重清洗")
        return
    cache = sp.load_cache(sp.p(sp.CACHE_FILE))

    iface, tun = (sp.IFACE, None) if sp.IFACE else sp.detect_lan_ip()
    if tun and not iface:
        log("警告: 检测到 VPN/TUN(%s) 且未找到物理网卡 IP, 建议在 shodan_pipeline.py "
            "的 IFACE 里手动填本机 IP" % tun)
    log("开始重清洗 %d 个已保留 IP | 网卡: %s | 阈值: 总放大率 >= %.1fx"
        % (len(kept), iface or "自动", threshold))

    # 按记录里的端口分组, 同组 IP 一次性 masscan 扫完
    kept_new = {rec["ip"]: rec for rec in kept}
    removed = []
    groups = group_by_ports(kept)

    # ===== 第一阶段: 全部 masscan 探测回包, 无响应的直接清洗 =====
    opens_by_ports = {}  # (端口元组) -> masscan 开放 (ip,port) 集合
    alive = set()
    for ports, ips in sorted(groups.items()):
        ports_arg = ",".join(str(x) for x in ports)
        log("--- 探测 %d 个 IP (端口 %s) ---" % (len(ips), ports_arg))
        opens = sp.masscan_sweep(ips, ports_arg, sp.RATE, sp.RETRIES,
                                 sp.IFACE or None)
        opens_by_ports[ports] = opens
        alive |= {ip for ip, _port in opens}
        log("该组: 有回包 %d, 无回包 %d"
            % (len(alive & set(ips)), len(set(ips) - alive)))
    all_ips = {rec["ip"] for rec in kept}
    if mass_dead_guard(all_ips, alive):
        return
    dead = sorted(all_ips - alive)
    for ip in dead:  # 无响应: 清除并从缓存移除, 允许将来重新收录
        if kept_new.pop(ip, None) is not None:
            removed.append(ip)
        cache.discard(ip)
        log("  [-] %s 清洗 (无响应)" % ip)
    log("第一阶段完成: 有回包 %d, 清除无响应 %d"
        % (len(alive & set(kept_new)), len(dead)))

    # ===== 第二阶段: 只对有回包的 IP 实测放大倍率/吞吐量 =====
    for ports, ips in sorted(groups.items()):
        ips_alive = sorted(alive & set(ips))
        if not ips_alive:
            continue
        opens = {(ip, p) for ip, p in opens_by_ports[ports] if ip in ips_alive}
        log("--- 实测 %d 个 IP (端口 %s) ---" % (len(ips_alive), ",".join(map(str, ports))))
        results = sp.measure_all(opens, sp.WAIT, iface)
        qualified, bad = sp.classify(results, ips_alive)
        for rec in qualified:  # 仍达标: 更新为新实测数据
            kept_new[rec["ip"]] = rec
            port = rec["ports"][0]
            extra = ""
            if port.get("rate_test"):
                extra = ", 回包 %s 包/秒" % port["rate_test"]["resp_pps"]
            log("  [+] %s %d/udp 单包 %.2fx 总 %.2fx (%d包%s) 保留"
                % (rec["ip"], port["port"], port["single_ratio"],
                   port["total_ratio"], port["packets"], extra))
        for ip in bad:         # 有回包但放大率不足: 清除
            got = [r for r in results.get(ip) or [] if r["sizes"]]
            best = max((sum(r["sizes"]) + sp.scan_gui.UDP_HDR * len(r["sizes"]))
                       / r["req"] for r in got) if got else 0.0
            if kept_new.pop(ip, None) is not None:
                removed.append(ip)
            cache.discard(ip)
            log("  [-] %s 清洗 (总放大率 %.2fx < %.1fx)" % (ip, best, threshold))
        log("该组: 达标 %d, 清除 %d" % (len(qualified), len(bad)))

    out = sorted(kept_new.values(),
                 key=lambda x: x.get("best_total_ratio", 0), reverse=True)
    sp.save_kept(out, sp.p(sp.KEPT_FILE))
    sp.save_cache(cache, sp.p(sp.CACHE_FILE))

    log("=" * 50)
    log("重清洗完成: 原来 %d 个 -> 现存 %d 个, 清除失效 %d 个"
        % (len(kept), len(out), len(removed)))
    for ip in sorted(removed):
        log("  [-] %s (已失效, 从缓存移除, Shodan 再爬到会重新测试)" % ip)
    if len(kept) - len(out) != len(removed):
        log("(部分 IP 因放大率更新后阈值变化而保留, 总数以文件为准)")


def main():
    ap = argparse.ArgumentParser(
        description="shodan_kept.json 重清洗工具")
    ap.add_argument("--filter", nargs="?", const=0.0, default=None, type=float,
                    metavar="倍数",
                    help="轻量清洗(不发任何包): 清除已记录总放大率低于阈值的 IP; "
                         "倍数省略时用 shodan_pipeline.py 的 MIN_TOTAL_RATIO")
    ap.add_argument("--dead", action="store_true",
                    help="无响应清洗: masscan 探测回包, 无回包的 IP 直接清除, "
                         "不测放大倍率")
    args = ap.parse_args()
    backup_files()
    if args.filter is not None:
        light_filter(args.filter if args.filter > 0 else sp.MIN_TOTAL_RATIO)
    elif args.dead:
        prune_dead()
    else:
        full_reclean()
    github_sync.push("reclean 重清洗完成")


if __name__ == "__main__":
    main()
