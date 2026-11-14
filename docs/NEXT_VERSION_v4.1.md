# httpmon v4.0.0 评估与下一个版本（v4.1.0）规划

> **状态**：已在 v4.1.0 实现（A–F）。

基线：`v4.0.0`（main = `76f8c79`，已发布）。
本文的数据都是在发布后的 v4.0.0 二进制上实测的，测试环境是 Linux amd64、Go 1.26。

v4.0 把 httpmon 从"包一层命令"变成了"会话 + 常驻代理 + 规则 + MCP"。
这个版本的问题不在缺功能。**v4.0 新增的场景（常驻代理、长会话、agent 通过 MCP 反复读）一放大就暴露了短板**：
会话越大越慢、越占内存；`--append` 的编号会冲突；`--follow` 在会话重启后会静默失效；常驻代理没有交互界面。
v4.1 是一个**兼容的小版本**，先把这些修好，再补几项让 v4.0 新场景真正可用的能力。

---

## 第一部分：v4.0.0 实测

### 达标的部分

| 项目 | 实测 | 结论 |
|---|---|---|
| 常驻代理内存 | 连续 3 轮各 2 万请求（20 并发，2 KB 响应），RSS 14.6 → 17.9 → 17.7 → 17.8 MB | 无泄漏，长期运行可行 |
| 代理吞吐 | 4.3–5.0k req/s（20 并发，含写会话） | 足够开发场景 |
| 规则、mock、MCP、安装路径 | 发布后用真实 release 验证过（install.sh、`go install …/v4/cmd/httpmon@v4.0.0`、`--mock` 冒烟） | 正常 |
| CI | Linux/macOS/Windows、lint、fuzz、性能预算、安装脚本与镜像构建全部通过 | 正常 |

### 问题（按严重程度）

**P1 会话一大，读取全部变成全量扫描，部分路径内存随会话线性增长。**
用常驻代理采集 6 万次交换，会话文件 165 MB：

| 操作 | 耗时 | 峰值内存 |
|---|---|---|
| `query long`（列出全部） | 4.26 s | 16 MB |
| `query long --id 59000`（取一条） | 1.67 s | 15 MB |
| `query long --status 5xx` | 1.68 s | 16 MB |
| `query long --grep …` | 1.89 s | 17 MB |
| `query long --format har` | 5.42 s | **1360 MB** |
| `diff long long` | 6.24 s | **1047 MB** |
| MCP `get_exchange`（取一条） | 1.62 s | **364 MB** |
| MCP `query_exchanges`（limit 20） | 1.70 s | **400 MB** |
| `mock long` 启动 | 1.96 s | — |

- 取一条交换要扫全文件。MCP 的每次工具调用都把整个会话读进内存（`readExchanges`）。
  agent 一轮对话里会调用十几次，等待和内存都按次数叠加。
- HAR 和 diff 把所有交换连同原始字节一起放进内存，峰值内存约为会话文件大小的 6–8 倍。
- 会话没有上限：同样的负载每 2 万次交换约增长 55 MB。常驻代理接浏览器流量一天可以到 GB 级，没有轮转，也没有清理命令。

**P1 `--append` 时编号冲突。** 每次运行的编号都从 1 开始：

```
$ httpmon --session app --append -- curl …/run1
$ httpmon --session app --append -- curl …/run2
$ httpmon query app
#1 GET 127.0.0.1:18601/run1 → 404 …
#1 GET 127.0.0.1:18601/run2 → 404 …
```

`query --id 1` 会同时命中两条，MCP 的 `get_exchange` 则静默返回第一条，agent 可能拿错数据。
`--mock-from` 按编号排序，多次运行的响应也会交错。

**P2 `query --follow` 在会话重新开始后静默失效。** 新一次运行会删除旧的 `exchanges.ndjson` 再新建文件。
正在 follow 的进程仍然读着已删除的旧文件，看不到新流量，也不报错（已复现）。

**P2 常驻代理没有交互界面。** `--ui` 只能配合被包裹的命令使用：`httpmon proxy --ui` 报 `flag provided but not defined`。
对照的顶级产品（Charles、Proxyman、HTTP Toolkit）在这个场景的核心正是实时界面。
TUI 已经具备搜索、详情、复制为 curl 等能力，但它只能吃进程内事件，读不了会话。

**P2 agent 没有"等某个请求发生"的原语。** agent 驱动浏览器或测试时，常见的需求是"等到下单请求出现再看它的响应"。
现在只能反复轮询 `query`，而在大会话上每轮都要 1.7 s。

**P3 规则只能按方法、主机和路径匹配。** 不能按请求头匹配（例如只让带某个 token 的请求失败），也不能改写头部（例如去掉 `Cache-Control`、注入调试头）。
这是 Charles 的 Rewrite、Proxyman 的 Map Local 最常用的部分。

**P3 发布矩阵缺 Windows arm64。** install.ps1 遇到 ARM64 直接报错。

### 维持不变的判断

- **透明 / 系统级拦截**（包括 Go 客户端不走代理访问 loopback 的问题）：继续推迟。
  它需要修改系统代理或网络设置，出错时会影响整台机器，收益只覆盖少数客户端。
- **GUI、HTTP/3、脚本化、证书固定绕过**：仍然不做。

---

## 第二部分：v4.1.0 的内容

v4.1 是兼容版本：不改变任何已有的选项、输出格式和记录格式（记录仍是 v3），v4.0 的会话可以直接读。

### A 会话索引：读取不再随会话大小线性变慢（解决 P1）

- 写会话时同步维护 `exchanges.idx`。每条交换一行定长记录，内容为编号、在 `exchanges.ndjson` 中的偏移和长度，以及摘要字段：方法、状态、错误类型、耗时、URL 哈希、规则标记。
- 用到索引的地方：
  - `query --id`、MCP 的 `get_exchange` 和 `get_body` 直接按偏移读一条；
  - `--status`、`--method`、`--error`、`--rule` 先在索引上过滤，只读命中的记录；
  - MCP 的 `query_exchanges` 只读索引就能输出摘要行。
- 索引缺失或损坏（例如 v4.0 的会话）时自动从 ndjson 重建，失败就退回全量扫描。索引只是加速，不是数据来源。
- **HAR 和 diff 改成流式处理**：HAR 逐条编码写出；diff 先只读配对需要的字段，再按需读出需要比较的两条正文。
- 目标（在同一份 6 万条、165 MB 的会话上）：

| 操作 | 现在 | 目标 |
|---|---|---|
| `query --id`、MCP `get_exchange` | 1.6 s | < 50 ms |
| MCP `query_exchanges` | 1.7 s / 400 MB | < 200 ms / < 50 MB |
| `--format har` 峰值内存 | 1360 MB | < 100 MB |
| `diff` 峰值内存 | 1047 MB | < 150 MB |

  性能预算测试会把其中两项（`--id` 耗时、HAR 峰值内存）加进 CI。

### B 会话的正确性和生命周期（解决 P1、P2）

- **`--append` 续接编号**：打开会话时从索引（或文件末尾）读出最大编号，新运行从下一个编号开始。
  这样编号在一个会话内唯一，`query --id`、MCP 和 `--mock-from` 不再有歧义。
- **`--follow` 跟随重启**：检测到文件被替换（inode 变化）或被截断时重新打开，并在输出中提示"会话已重新开始"。
- **上限与轮转**：新增 `--max-session-size`。`httpmon proxy` 默认 1 GB，包裹命令时默认不限制。
  超过上限时，丢弃最老的一段，按分段文件 `exchanges.N.ndjson` 轮转，索引跨段。
- **清理命令**：
  - `httpmon sessions rm NAME…`：正在运行的会话拒绝删除；
  - `httpmon sessions prune --older-than 7d`：只删除已结束的会话。
- `httpmon sessions` 的 JSON 输出增加交换数、首末时间和是否被截断。

### C `httpmon ui`：会话的交互界面（解决 P2）

- `httpmon ui SESSION` 打开现有 TUI，数据来自会话而不是进程内事件。
  打开时先从索引载入最近 N 条；如果会话正在运行，随后像 `--follow` 一样实时追加，并显示进行中的请求（来自 `live.json`）。
- `httpmon proxy --ui` 等价于启动代理后打开 `httpmon ui proxy`。
- TUI 现有的搜索、详情、复制为 curl、导出全部保留；新增按 `[mock]`/`[fault]`/`[map]` 过滤，以及从当前条目一键 `replay`（只读模式下禁用）。
- 包裹命令时的 `--ui` 行为不变。

### D 面向 agent：等待与导出（解决 P2）

- **CLI**：`httpmon query NAME --wait --status 5xx --url /orders --timeout 30s`，阻塞直到出现第一条匹配的交换，然后输出它。
  超时退出码为 4，与 `--fail-on` 的 3 区分开。这一功能建立在 B 的 follow 之上。
- **MCP**：
  - 新增 `wait_for_exchange`，参数与上面相同，服务端最多等待 `timeout` 秒，超过 60 s 时截断为 60 s；
  - 新增 `export_curl`，只读，输出已脱敏的 curl 命令；
  - 新增 `replay_exchange`，因为它会对外发请求，所以和 `add_rule` 一样需要 `--allow-mutations`。
- 所有 MCP 读取都走 A 的索引，每次调用的耗时与会话大小无关。

### E 规则增强（解决 P3）

- 匹配条件可以加请求头：`--fault 'POST api.example.com/pay [header X-Test-Fail] => reset'`、
  `--mock 'GET */me [header Authorization: Bearer expired*] => 401'`。
  方括号内是一个头名和可选的值通配，可以写多个，彼此是"与"的关系。
- 新增 `--header` 规则改写头部：`--header 'api.example.com/* => response remove Cache-Control'`、
  `--header '*/api/* => request set X-Debug: 1'`。被改写的交换标记为 `[header]`。
- 项目配置文件里的这些规则同样受 v4.0 的安全限制（只能 map 到本机）。
  对 `--header` 另加一条：项目文件里的规则不能设置 `Authorization`、`Cookie` 或 `Proxy-Authorization`。

### F 交付（解决 P3）

- 发布矩阵加入 `windows/arm64`，install.ps1 支持 ARM64。
- CI 的 Ubuntu 任务曾排队超过 3 小时，原因之一是同一提交的 push 和 pull_request 各跑一遍。
  为 CI 加 `concurrency`（同一分支只保留最新一次运行），PR 分支只在 `pull_request` 事件上运行。

---

## 第三部分：不在 v4.1 做的事

| 项目 | 理由 |
|---|---|
| 系统代理自动配置（`--system`） | 修改系统网络设置，进程异常退出时会让整机断网；推迟到有可靠的恢复机制再说 |
| 透明 / 按进程拦截 | 同上，跨平台成本高 |
| 由会话推断 OpenAPI 规范 | 对 agent 有价值，但属于新产品面，放到 v5 评估 |
| 断点 / 交互式改包 | 需要阻塞式 UI 和超时策略，与"规则是声明式的"这一设计冲突；先观察 E 能覆盖多少需求 |

---

## 第四部分：发布节奏

一个 PR、一个版本 `v4.1.0`，按依赖顺序实现：

1. B 的编号续接和 follow 修复（独立的 bug 修复，最先做）
2. A 索引与流式 HAR/diff（C、D 依赖它）
3. D 等待与 MCP 新工具
4. C `httpmon ui`
5. E 规则增强
6. F 交付与 CI 并发
7. 测试（包括会话大小的性能预算）、README、CHANGELOG `[4.1.0]`、`help agents`、skill

**兼容性承诺**：v4.0 的全部选项、输出和会话格式不变。新增的文件（`exchanges.idx`、分段文件）会被 v4.0 的 httpmon 忽略；当前段仍叫 `exchanges.ndjson`，v4.0 能读到最新一段，但读不到已轮转的旧段。
