# -*- coding: utf-8 -*-
"""重清洗: 把 shodan_kept.json 里失效 / 放大率不足的 IP 清洗出去

两种模式:
1. 全量重测 (默认, 不带参数): python reclean.py
   对每个 IP 按其记录的端口重新实测 (masscan + 体积比/吞吐量):
   - 仍达标 -> 更新记录(新的体积比/吞吐量)
   - 不达标(含无响应) -> 从 kept.json 清除, 并从 _tested_cache.json 移除
     (之后 Shodan 再爬到它时流水线会重新测试, 恢复了可再次收录)
2. 轻量清洗 (不发任何包): python reclean.py --filter [倍数]
   只按已记录的总放大率过滤, 低于阈值的 IP 直接清除。
   适合快速清理, 但发现不了"记录达标但实际已失效"的 IP

命令行参数:
  --filter [倍数]   轻量清洗模式; 倍数省略时用 shodan_pipeline.py 的 MIN_TOTAL_RATIO

注意: 全量重测模式运行前请勿同时运行 shodan_pipeline.py (会抢 masscan 临时文件)
"""
import argparse

import shodan_pipeline as sp

# ================【可自定义配置】================
# 全量重测模式的阈值: None = 沿用 shodan_pipeline.py 的 MIN_TOTAL_RATIO
# 也可单独填一个值, 如 15.0 (对旧 IP 要求更严格)
MIN_TOTAL_RATIO = None
# ================================================

log = sp.log


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
    groups = {}  # (端口元组) -> [ip, ...]
    for rec in kept:
        ports = tuple(sorted({int(x["port"]) for x in rec.get("ports", [])
                              if isinstance(x, dict) and "port" in x}))
        groups.setdefault(ports, []).append(rec["ip"])

    kept_new = {rec["ip"]: rec for rec in kept}
    removed = []
    for ports, ips in sorted(groups.items()):
        ports_arg = ",".join(str(x) for x in ports)
        log("--- 重测 %d 个 IP (端口 %s) ---" % (len(ips), ports_arg))
        opens = sp.masscan_sweep(ips, ports_arg, sp.RATE, sp.RETRIES,
                                 sp.IFACE or None)
        log("masscan 发现 %d 个开放 (ip,port) 对" % len(opens))
        results = sp.measure_all(opens, sp.WAIT, iface) if opens else {}
        qualified, bad = sp.classify(results, ips)
        for rec in qualified:  # 仍达标: 更新为新实测数据
            kept_new[rec["ip"]] = rec
        for ip in bad:         # 失效: 清除并从缓存移除, 允许将来重新收录
            if kept_new.pop(ip, None) is not None:
                removed.append(ip)
            cache.discard(ip)
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
    args = ap.parse_args()
    if args.filter is not None:
        light_filter(args.filter if args.filter > 0 else sp.MIN_TOTAL_RATIO)
    else:
        full_reclean()


if __name__ == "__main__":
    main()
