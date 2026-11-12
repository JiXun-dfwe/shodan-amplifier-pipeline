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
├── send_reflect.py      # send-only 反射发包工具: 指定时长/带宽发探测包, 测试模式可校准实际反射流量
├── scan_gui.py          # masscan 可视化扫描工具 (tkinter GUI)
├── ssdp_payloads.txt    # SSDP 探针载荷 (与实测放大率用的探针逐字节一致, 供 send_reflect.py 加载)
├── shodan_kept.json     # 合格 IP 汇总 (按 best_total_ratio 降序)
├── _tested_cache.json   # 已测试 IP 缓存 (防重复测试)
└── masscan/             # masscan 源码 (含 send-only/duration/bandwidth/count-file 扩展)
```

## 环境要求

- **Windows**（masscan.exe 路径默认按 Windows 写死，其他平台需自行修改）
- **Python 3.8+**，依赖：

  ```bash
  pip install requests beautifulsoup4
  ```
- **masscan.exe**：二进制不入库，自行编译或获取后放到 `masscan/bin/masscan.exe`。
  可直接编译本仓库 `masscan/` 源码（含本项目扩展的 send-only 等功能）：
  - Windows: 用 `masscan/vs10/masscan.sln` 编译（需先下载 [npcap SDK](https://npcap.com/dist/) 解压到 `masscan/vs10/include` 和 `vs10/lib`）
  - Linux: `cd masscan && make`
- 以**管理员权限**运行（masscan 需要原始套接字收发包）。

## 配置：环境变量 / .env 文件

所有参数通过**环境变量**配置，均有默认值，不设置即可运行。两个来源，优先级从高到低：

1. **系统环境变量**（PowerShell `$env:XXX`，只对当前终端生效）
2. **`.env` 文件**（脚本同目录，长期生效，推荐）：复制 `.env.example` 为 `.env` 后填写。
   `.env` 已被 gitignore，**Cookie 等敏感信息只放这里，不要提交**

四个脚本的前缀互不混杂：
`SDP_`（主流水线）、`RC_`（重清洗）、`SR_`（反射发包）、`GUI_`（可视化扫描）。

PowerShell 设置示例：

```powershell
Copy-Item .env.example .env; notepad .env   # 或者直接设环境变量:
$env:SDP_COOKIE = "polito=粘贴你的Cookie"   # Cookie 含敏感信息, 只放 .env/环境变量, 不要写进源码
$env:SDP_SEARCH_QUERY = "port:1900"
$env:SR_DURATION = "30"
$env:SR_BANDWIDTH = "8"
python shodan_pipeline.py
```

### shodan_pipeline.py — 前缀 `SDP_`

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `SDP_COOKIE` | 空 | **Shodan 登录 Cookie（必填）**。浏览器登录 shodan.io → F12 → 网络 → 任选请求 → 复制请求头 `Cookie` 整段值 |
| `SDP_SEARCH_QUERY` | `port:1900` | Shodan 搜索语句，决定爬取的目标服务类型 |
| `SDP_PORTS` | `auto` | `auto` 自动从 SEARCH_QUERY 提取 `port:XXXX`，也可手填 `"1900,123"` |
| `SDP_MIN_TOTAL_RATIO` | `15.0` | 保留阈值：总放大率达到该倍数才收录 |
| `SDP_WAIT` | `4.0` | 体积比实测每端口等待响应秒数（SSDP 多包设备建议 4-5） |
| `SDP_IFACE` | 空 | 留空自动检测网卡；检测到 VPN/TUN 时手动填物理网卡 IP |
| `SDP_RATE` | `1000` | masscan 每秒发包速率 |
| `SDP_RETRIES` | `2` | masscan 重发次数（2 = 共发 3 次） |
| `SDP_RATE_TEST` | `1` | 是否测回包吞吐量（`0` 关闭） |
| `SDP_RATE_TEST_DURATION` | `3.0` | 吞吐量测试时长（秒） |
| `SDP_RATE_TEST_PPS` | `50` | 吞吐量测试每秒发包数 |
| `SDP_MAX_ROUNDS` | `0` | 爬取轮数，0 = 无限循环 |
| `SDP_POLL_INTERVAL` | `60,120` | 每轮爬取间隔秒数（下限，上限） |
| `SDP_PAGE_INTERVAL` | `2,4` | 同一轮内两个 page 之间间隔秒数 |
| `SDP_TIMEOUT` | `5` | HTTP 请求超时（秒） |
| `SDP_KEPT_FILE` | `shodan_kept.json` | 合格 IP 汇总文件 |
| `SDP_CACHE_FILE` | `_tested_cache.json` | 已测试 IP 缓存文件 |
| `SDP_MASSCAN` | 自动 | masscan.exe 路径覆盖 |

### reclean.py — 前缀 `RC_`

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `RC_MIN_TOTAL_RATIO` | 沿用 `SDP_MIN_TOTAL_RATIO` | 全量重测的保留阈值 |
| `RC_MAX_DEAD_RATIO` | `0.7` | 断网保护：无响应 IP 超过该比例时中止且不写盘，设 `1` 关闭 |

### send_reflect.py — 前缀 `SR_`

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `SR_DURATION` | `30` | 发包持续秒数（命令行 `--duration` 可覆盖） |
| `SR_BANDWIDTH` | `8.0` | 发包流量目标 Mbps，masscan 按实测包长自动换算 pps（`--bandwidth` 可覆盖） |
| `SR_RATIO_RANGE` | `15,20` | 放大倍率筛选区间：`50` = ≥50；`15,20` = 闭区间；`50,` = ≥50 |
| `SR_SOURCE_IP` | 空 | 伪造源 IP（`--source-ip` 可覆盖），留空用本机网卡 |
| `SR_PORTS` | `auto` | 自动从选中记录汇总端口，或手填 `"1900,123"` |
| `SR_IFACE` | 空 | 本机网卡 IP，留空让 masscan 自动选择 |
| `SR_OFFLINE` | `0` | `1` = 只走流程不真发包（流程测试用） |
| `SR_REFLECT_TAIL` | `10` | 测试模式发包结束后继续抓反射的收尾秒数 |
| `SR_KEPT_FILE` | `shodan_kept.json` | IP 汇总文件 |
| `SR_MASSCAN` | 自动 | masscan.exe 路径覆盖 |

### scan_gui.py — 前缀 `GUI_`

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `GUI_MASSCAN` | 自动 | masscan.exe 路径覆盖 |

## 快速开始

### 1. 运行主流水线

```bash
# 管理员权限运行 (先设置 SDP_COOKIE, 见上节)
python shodan_pipeline.py
```

运行后进入无限循环：爬取 → 新 IP 立即实测 → 达标的追加进 `shodan_kept.json`。**Ctrl-C 随时停止**，每轮结束数据都已写盘，不会丢失。

### 2. 重清洗失效 IP

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

### 3. 反射发包 (send_reflect.py)

从 `shodan_kept.json` 按放大倍率区间筛选 IP，生成列表交给扩展版 masscan **只发包不收包**：
指定发包时长和目标带宽（Mbps，按实测包长自动换算 pps），每 IP 发包数记录到 CSV，
速率日志每秒一行，可实时监控实际发送流量。

```bash
# 基本用法: 发 30 秒, 8 Mbps
python send_reflect.py --duration 30 --bandwidth 8

# 伪造源 IP (反射流量会打向该 IP, 仅限授权测试!)
python send_reflect.py --duration 30 --bandwidth 8 --source-ip 192.168.1.50

# 测试模式: 不伪造源 IP, 抓取实际反射回来的流量, 与理论值对比并校准有效倍率
#   (需要管理员权限: 同时要发包 + SIO_RCVALL 抓包)
python send_reflect.py --test --duration 15 --bandwidth 0.5
```

输出文件（`_` 开头，已 gitignore）：
- `_send_il.txt` — 发给 masscan 的 IP 列表
- `_send_counts.csv` — 每个 IP 的发包数
- `_send_rate.csv` — 每秒速率日志（时间戳、pps、Mbps）
- `_masscan_console.log` — masscan 控制台输出

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
Cookie 过期或未填。重新从浏览器复制 Cookie 到环境变量 `SDP_COOKIE`。

**Q: 检测到 VPN/TUN 警告？**
本机开了 VPN/TUN 虚拟网卡（198.18.x 段）导致自动检测失败。在 `SDP_IFACE` 手动填本机物理网卡 IP。

**Q: 想测其他协议？**
改 `SDP_SEARCH_QUERY` 即可，如 `"port:53"`（DNS）、`"port:161"`（SNMP）、`"port:123"`（NTP）。`SDP_PORTS` 保持 `auto` 会自动提取端口；多端口协议手填如 `"1900,123"`。

**Q: masscan 报错无法发包？**
确认以管理员权限运行，且 `SDP_IFACE` 填的是物理网卡 IP（虚拟网卡/VPN 网卡会导致 masscan 选错出口）。

**Q: 为什么 Cookie 要放环境变量而不是源码里？**
源码会推送到 GitHub，Cookie 是登录凭据，入库即泄露。环境变量只存在于本机。若曾不小心提交过，应立即在 Shodan 退出登录使 Cookie 失效。
