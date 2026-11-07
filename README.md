# Shodan Amplifier Pipeline

Shodan 爬虫 + masscan UDP 放大测试一体化流水线。循环爬取 Shodan 搜索结果，对每个新发现的 IP 立即实测 UDP 放大效果（体积比 + 回包吞吐量），只保留放大率达标的 IP，自动维护一份持续更新、按放大率降序排列的合格 IP 汇总。

> ⚠️ **免责声明**：本项目仅供网络安全研究与授权测试使用。对任何你未获得明确授权的网络主机发送探测流量可能违反当地法律法规。使用者需自行承担全部责任。

## 工作原理

```
Shodan 搜索结果页 (Cookie 登录态)
        │  每轮抓取 page=1、2，解析出新 IP
        ▼
masscan UDP 扫描 (--banners)  ──► 发现开放端口
        ▼
逐端口实测 (masscan 探测载荷)
  ├─ 体积比: 单包最大放大率 / 总放大率
  └─ 吞吐量: 回包 包/秒、字节/秒
        ▼
总放大率 >= MIN_TOTAL_RATIO ?
  ├─ 是 → 写入 shodan_kept.json (持续累加)
  └─ 否 → 丢弃，IP 记入 _tested_cache.json 防止重测
```

- 每轮循环抓取间隔 60~120 秒（Shodan 结果约 1-2 分钟刷新一次），直到 Ctrl-C 停止，随时停止数据都完整。
- 已测试过的 IP（无论合格与否）记录在缓存中，不会重复测试。
- 每轮开始会重新读盘，因此运行流水线期间用 `reclean.py --filter` 清洗也能生效。

## 目录结构

```
├── shodan_pipeline.py   # 主流水线: 爬取 + 扫描 + 实测 + 存储
├── reclean.py           # 重清洗工具: 清理失效/不达标 IP
├── scan_gui.py          # masscan 可视化扫描工具 (tkinter GUI)
├── shodan_kept.json     # 合格 IP 汇总 (按 best_total_ratio 降序)
└── _tested_cache.json   # 已测试 IP 缓存 (防重复测试)
```

## 环境要求

- **Windows**（masscan.exe 路径默认按 Windows 写死，其他平台需自行修改 `MASSCAN` 常量）
- **Python 3.8+**，依赖：

  ```bash
  pip install requests beautifulsoup4
  ```
- **masscan.exe**：本仓库不含 masscan 二进制。请从 [masscan 官方仓库](https://github.com/robertdavidgraham/masscan) 编译或获取 Windows 版本，放到 `masscan/bin/masscan.exe`（与脚本同目录下的 `masscan/bin/`）。
- 以**管理员权限**运行（masscan 需要原始套接字收发包）。

## 快速开始

### 1. 配置

编辑 `shodan_pipeline.py` 顶部的【可自定义配置】区：

```python
# ---- Shodan 爬虫 ----
SEARCH_QUERY = "port:1900"   # 搜索参数, 如 "port:53"、"port:161"、"ssdp"
COOKIE = "polito=在这里粘贴你的Shodan登录Cookie"

# ---- UDP 测试 ----
MIN_TOTAL_RATIO = 15.0       # 保留阈值: 总放大率达到该倍数才保留
IFACE = ""                   # 本机物理网卡 IP, 留空自动检测
RATE_TEST = True             # 是否测回包吞吐量
```

**获取 Cookie**：Shodan 的搜索过滤器（如 `port:1900`）需要登录才能用。浏览器登录 shodan.io → F12 → 网络(Network) → 任选请求 → 复制请求头 `Cookie` 的整段值粘贴到 `COOKIE`。

**关键参数说明**：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `SEARCH_QUERY` | `port:1900` | Shodan 搜索语句，决定爬取的目标服务类型 |
| `PORTS` | `auto` | `auto` 表示自动从 `SEARCH_QUERY` 提取 `port:XXXX`，也可手填 `"1900,123"` |
| `MIN_TOTAL_RATIO` | `15.0` | 保留阈值：总放大率达到该倍数才收录 |
| `WAIT` | `4.0` | 体积比实测每端口等待响应秒数（SSDP 多包设备建议 4-5） |
| `IFACE` | `""` | 留空自动检测网卡；检测到 VPN/TUN 时会警告，此时手动填物理网卡 IP |
| `RATE` | `1000` | masscan 每秒发包速率 |

### 2. 运行主流水线

```bash
# 管理员权限运行
python shodan_pipeline.py
```

运行后进入无限循环：爬取 → 新 IP 立即实测 → 达标的追加进 `shodan_kept.json`。**Ctrl-C 随时停止**，每轮结束数据都已写盘，不会丢失。

### 3. 重清洗失效 IP

IP 会失效（重启、修复漏洞、下线），定期重清洗可以让列表保持有效：

```bash
# 全量重测 (默认): 对每个 IP 重新实测
#   仍达标   -> 更新记录 (新的体积比/吞吐量)
#   不达标   -> 清除出 kept.json, 并从缓存移除 (之后 Shodan 再爬到会重新测试)
python reclean.py

# 轻量清洗 (不发任何包): 只按已记录的总放大率过滤, 秒级完成
#   发现不了"记录达标但实际已失效"的 IP
python reclean.py --filter        # 阈值沿用 shodan_pipeline.py 的 MIN_TOTAL_RATIO
python reclean.py --filter 20     # 自定义阈值 20 倍
```

> 注意：全量重测模式运行前**请勿同时运行** `shodan_pipeline.py`（会抢 masscan 临时文件）。

### 4. 可视化扫描 (可选)

```bash
python scan_gui.py
```

独立的 tkinter GUI 工具，手动输入 IP/端口范围做 masscan UDP 扫描和放大率实测。主流水线复用了它的 `measure_ratio` / `rate_test` 实测逻辑。

## 数据文件格式

### shodan_kept.json — 合格 IP 汇总

按 `best_total_ratio` 降序排列，同 IP 重复出现时只在新放大率更高时更新：

```json
[
  {
    "ip": "1.2.3.4",
    "best_total_ratio": 30.71,
    "ports": [
      {
        "port": 1900,
        "req_bytes": 112,
        "packets": 3,
        "sizes": [3452, 1204, 899],
        "single_max_bytes": 3472,
        "single_ratio": 31.0,
        "total_bytes": 5575,
        "total_ratio": 30.71,
        "rate_test": {
          "resp_pps": 45,
          "resp_bytes_per_sec": 158230,
          "sent_requests": 150
        }
      }
    ]
  }
]
```

- `single_ratio`：单包最大放大率（最大回包/请求）
- `total_ratio`：总放大率（全部回包之和/请求），收录依据
- `rate_test`：吞吐量测试结果（关闭 `RATE_TEST` 时无此字段）

### _tested_cache.json — 已测试缓存

```json
{ "ips": ["1.2.3.4", "5.6.7.8"] }
```

防止重复测试。**删除后会全部重测**。

## 常见问题

**Q: 提示 "Shodan 要求登录"？**
Cookie 过期或未填。重新从浏览器复制 Cookie 到 `COOKIE` 配置。

**Q: 检测到 VPN/TUN 警告？**
本机开了 VPN/TUN 虚拟网卡（198.18.x 段）导致自动检测失败。在 `IFACE` 手动填本机物理网卡 IP。

**Q: 想测其他协议？**
改 `SEARCH_QUERY` 即可，如 `"port:53"`（DNS）、`"port:161"`（SNMP）、`"port:123"`（NTP）。`PORTS` 保持 `auto` 会自动提取端口；多端口协议手填如 `"1900,123"`。

**Q: masscan 报错无法发包？**
确认以管理员权限运行，且 `IFACE` 填的是物理网卡 IP（虚拟网卡/VPN 网卡会导致 masscan 选错出口）。
