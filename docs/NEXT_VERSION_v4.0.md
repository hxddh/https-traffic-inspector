# httpmon v3.1.0 评估与下一个大版本（v4.0.0）规划：按顶级产品的标准

基线：`v3.1.0`（main = `eb11a30`，已发布）。约 1.4 万行 Go（含测试），179 个测试函数，`-race` 干净，lint 0 issues。

**维护者决定**：v4.0 不需要兼容历史版本和旧数据。**评估标准**：按顶级产品的水准，而不是"比上个版本好"。

对照的产品是这个领域公认的几款：**mitmproxy**、**Charles**、**Proxyman**、**HTTP Toolkit**、**Fiddler**，
以及浏览器里的 **Chrome DevTools Network 面板**。httpmon 不打算变成它们，
但"顶级"意味着在自己选择的定位上，每一项都要做到不输它们，并且有它们没有的东西。

证据分三类，每条都会标注：
- **实测**：对 v3.1.0 发布的二进制做了测量；
- **走查**：读代码得出；
- **公开资料**：竞品的能力来自它们的公开文档和广为人知的功能。我没有在这个环境里运行这些竞品，所以这类结论只用来定位方向，不作为数字依据。

---

## 第一部分：v3.1.0 的现状，用顶级产品的尺子量

### 已经达到或超过顶级水准的部分（实测）

| 维度 | 测量 | 结论 |
|---|---|---|
| 单请求延迟开销 | 串行 2000 个请求：直连 p50 110µs，经 httpmon p50 370µs（**+0.26 ms**） | 对调试代理来说可以忽略 |
| 吞吐 | 50 并发：直连 61k rps，经 httpmon 9.2k rps（HTTPS 隧道 8.8k，开启 `--record` 7.2k），0 错误 | 远超调试场景的需要。Python 实现的代理通常在数百到数千 rps 量级（公开资料，未实测） |
| 启动 | `httpmon -o /dev/null true` 端到端 **17–19 ms** | 可以随手包在任何命令前；GUI 类产品需要启动一个应用 |
| 零配置覆盖 | 8 种客户端中有 7 种不做任何配置就能抓到：curl、wget、Python urllib、Python requests、Node `fetch`、Node `https.get`、访问非回环地址的 Go net/http（Java 在 v2.0 时已实测通过） | 这是 httpmon 最强的差异化：竞品大多需要用户配置系统代理或手动信任 CA |
| 解析器健壮性 | 对 protobuf 解码、JSON 结构截断、body 渲染、WebSocket 帧解析、终端转义做 fuzz，各跑 30 秒，共约 330 万次输入：**0 崩溃，0 次转义被绕过** | 健壮 |
| agent 接口 | 摘要格式、`--fail-on`、`query`、`diff`、JSON Schema、`help agents` | 竞品都没有这一层（公开资料）：它们是为人和 GUI 设计的 |

### 与顶级产品的差距

| # | 差距 | 依据 | 顶级产品的做法（公开资料） |
|---|---|---|---|
| G1 | **只能包装自己启动的命令**。浏览器、手机、模拟器、容器、已经在运行的服务都没法接入；README 里没有"作为独立代理运行"的说明 | 走查 | Charles、Proxyman、Fiddler 的核心用法都是"作为系统代理或设备代理"；mitmproxy 有常规模式和透明模式 |
| G2 | **只能看，不能改**：不能 mock 响应、注入故障（5xx、延迟、断连）、把请求改写到别处 | 走查 | 五款竞品都有 Map Local / Map Remote / 断点 / 改写 / mock，这是这一品类的标配 |
| G3 | **分发是半成品**：Release 只有 5 个裸二进制，没有校验和文件、签名或来源证明；没有 Homebrew、Scoop 或容器镜像；macOS 二进制没有签名和公证（从浏览器下载会被 Gatekeeper 拦截）；`go install` 装出的二进制叫 `https-traffic-inspector`，不叫 `httpmon` | 实测 | 顶级 CLI 工具都提供包管理器安装、校验和、签名，macOS 上还会公证 |
| G4 | **只在 Linux 上测试**：CI 只在 ubuntu 上跑。Windows 和 macOS 的二进制每个版本都发布，但从未运行过任何测试（信号转发、TTY 检测、路径、CA bundle 这些都依赖平台） | 实测（`ci.yml` 中只有 `runs-on: ubuntu-latest`） | 顶级产品在每个支持的平台上都跑 CI |
| G5 | **质量门不完整**：fuzz 没有进 CI，性能没有回归基线，端到端测试只覆盖 curl | 走查 | 成熟项目会做持续 fuzz 和基准测试 |
| G6 | **抓不到不认代理环境变量的程序**：Go 访问回环地址（实测抓不到）、静态链接并自带根证书的程序（例如使用内置根证书的 rustls 客户端，走查）、容器里的进程 | 实测 + 走查 | HTTP Toolkit 按运行时逐个注入；mitmproxy 有按进程拦截的透明 / local 模式 |
| G7 | **查询能力停在"列出和展开"**：`query` 不能按 body 内容搜索，不能把选中的请求导出为 curl 或 HAR；HAR 只能在运行时用 `--har` 生成，事后不能从 record 导出 | 走查 | DevTools 和各家 GUI 都能全文搜索，能复制为 curl、导出 HAR |
| G8 | **没有配置文件**：每次运行都要带上参数，或者设环境变量 | 走查 | 竞品都有偏好设置和持久化的规则 |
| G9 | **常驻场景下 agent 看不到实时状态**：一次运行中途无法查询"现在哪些请求还在进行" | 走查 | GUI 产品天然就是实时视图 |

结论：httpmon 在**"包装一个命令，抓它的流量，交给人或 agent 分析"**这件事上已经是同类最好，
但"顶级产品"还要求三样它还没有的东西：**任何来源的流量都能接**（G1、G6）、**能改流量**（G2）、
**像产品一样交付**（G3、G4、G5）。

---

## 第二部分：v4.0 的定位

一句话：**终端和 agent 首选的 HTTP 调试代理**。不做 GUI，因为那是 Proxyman 和 Charles 的主场，追过去只会做出一个更差的 GUI。
把 GUI 产品做得好的事——任意来源接入、改写和 mock、全文查询——用 CLI 和 agent 的方式做到同等水平。
同时保持竞品没有的两点：零配置包装命令，以及专门为 agent 设计的输出。

### 不做的事（明确）

- **GUI 和 Web UI**：HAR 能直接导入 DevTools，"人用图形界面看"这件事交给现成工具；
- **HTTP/3 拦截**：客户端经过代理时本来就会退回 HTTP/1.1 或 HTTP/2，绝大多数竞品也没有支持；
- **脚本引擎**（mitmproxy 的 Python addon 那样的）：用声明式规则覆盖九成的用法，不引入一个可以执行任意代码的面；
- **证书固定绕过**：超出调试自己程序这个范畴。

---

## 第三部分：v4.0 的能力

### A ⚠ 一个 CLI，三种接入方式（解决 G1）

```bash
httpmon <command>                       # 包装命令（现有）
httpmon proxy [--port 8080] [--listen 0.0.0.0] [--session NAME]
                                        # 独立代理：浏览器、手机、模拟器、已在运行的服务
eval "$(httpmon env --session NAME)"    # 让当前 shell 后续的命令都经过一个正在运行的代理
```

- `httpmon proxy` 是一等公民：启动时打印接入说明（代理地址、CA 文件路径、iOS/Android/浏览器的信任步骤链接）；
  默认只监听 loopback，`--listen` 放开时沿用现有的警告。它自动使用持久 CA（`httpmon ca`），因为设备需要信任一次后长期有效；
- **会话（session）**：每个会话是一个目录，里面有 record、HAR 和状态文件。`httpmon` 包装命令时也写入一个会话。
  `query`、`diff`、`replay` 接受会话名代替文件路径；
- **实时状态**：代理把进行中的请求写进会话的状态文件，`httpmon query --session NAME --live` 能看到"现在哪些请求还没完成"（解决 G9）；
- `httpmon env` 输出 `HTTP(S)_PROXY`、各种 CA 变量、`JAVA_TOOL_OPTIONS` 等 export 语句，复用包装命令时注入的那一套环境，
  agent 在多次 shell 调用之间就能共用同一个代理。

### B 改写、mock 和故障注入（解决 G2）

声明式规则，写在命令行或配置文件里。不用脚本：

```bash
httpmon --mock 'GET api.example.com/v1/orders => 503 {"error":"maintenance"}' npm test
httpmon --fault 'POST */upload => reset after 1KB' ./sync.sh
httpmon --fault '* api.example.com/* => delay 2s 30%' pytest
httpmon --map 'api.example.com => localhost:8080' npm run dev
httpmon mock trace.ndjson --port 9000   # 用一份 record 当离线的 mock 服务器
```

- 匹配：方法 + 主机和路径的通配；动作包括固定响应（状态码、头、body，或者文件）、延迟、按比例生效、连接重置、超时、改写目标地址；
- **对 agent 的价值最大**：重试、超时、降级这些错误处理逻辑，以前要靠运气复现，现在可以确定性地测试。
  "让 /orders 返回 503，确认客户端会重试三次"成了一条命令。结合 `--fail-on`（agent 判定结果）和 `diff`（agent 判定变化），
  形成完整的"制造条件 → 运行 → 判定"闭环；
- 每个被规则改动的交换在输出和 record 里都会被标记（`mocked: rule 2`），摘要行带 `[mock]`，防止把注入的故障误当成真实故障；
- `httpmon mock <record>`：把录下的响应当作服务端回放，用于离线、确定性的测试（Charles 的 Map Local、HTTP Toolkit 的 mock 都是这类用法，公开资料）。

### C 产品级交付（解决 G3、G4、G5）

| 项 | 内容 |
|---|---|
| 二进制名 | ⚠ `main` 移到 `cmd/httpmon`：`go install github.com/hxddh/https-traffic-inspector/v4/cmd/httpmon@latest` 装出的就叫 `httpmon` |
| 安装渠道 | 安装脚本 `curl -fsSL …/install.sh \| sh`（自动选平台和架构，校验 SHA256 和来源证明，安装到 `~/.local/bin`）、PowerShell 版 `install.ps1`、`ghcr.io` 容器镜像（多架构）、`go install …/cmd/httpmon`。**不提供 Homebrew 和 Scoop**（维护者决定：不新建包管理器仓库） |
| 完整性 | 每个 Release 带 `SHA256SUMS`，用 GitHub Artifact Attestations 生成构建来源证明（`gh attestation verify` 可验证）、SBOM |
| macOS | **暂不签名、不公证**（维护者决定：暂无 Apple Developer 账号）。从浏览器下载的二进制会被 Gatekeeper 加上隔离属性而无法运行，因此 macOS 的推荐安装方式是安装脚本（用 curl 下载的文件不带隔离属性）、`go install`（本机编译）或容器镜像；README 和 Release 说明写明浏览器下载后用 `xattr -d com.apple.quarantine httpmon` 解除。这些安装方式都要在 macOS CI 上实际跑一遍 |
| 跨平台 CI | ubuntu、macOS、Windows 三平台跑完整测试，外加每个平台一组端到端测试（curl、Python、Node） |
| 质量门 | fuzz 目标进入仓库，CI 每次跑 30 秒，每晚跑 10 分钟；用 benchmark 守住性能基线（单请求开销、50 并发吞吐），回退超过 20% 时 CI 失败 |

### D 查询和导出（解决 G7）

```bash
httpmon query trace --grep 'order_id=42'           # 在 URL、头和解码后的 body 里搜索
httpmon query trace --id 10 --format curl          # 复制为 curl（TUI 里已有，CLI 里补上）
httpmon query trace --status 5xx --format har > failures.har   # 任意选择的请求导出成 HAR
```

⚠ `--har` 运行参数删除：HAR 改为从 record 或会话导出，整个工具只保留一种捕获格式。

### E 配置文件（解决 G8）

`~/.config/httpmon/config.toml` 和项目目录下的 `.httpmon.toml`：默认格式、`fail-on`、`ignore`、mock 和 fault 规则、
上游代理、持久 CA 路径。优先级：命令行 > 项目配置 > 用户配置 > 环境变量。agent 在项目里放一份配置，团队里每个人和每个 agent 的行为就一致了。

### F MCP server（v4.0 做）

前两次评估都推迟了 MCP，理由是"能运行 httpmon 的 agent 都有 shell"。A 改变了这个前提：
**独立代理会话的流量不是由 agent 运行的命令产生的**（浏览器、手机、IDE 里的服务），而这些场景里的 agent 往往没有 shell
（Claude Desktop、IDE 里的助手）。`httpmon mcp --session NAME` 提供以下工具，都建立在会话之上，复用 query 和 diff 的实现：
`list_exchanges`、`get_exchange`、`get_body`、`search`、`live`、`diff_sessions`、`add_mock`、`clear_mocks`。
只读工具默认开启；改写类工具（mock）需要显式的 `--allow-mutations`。

### G 透明 / 按进程拦截（评估后推迟）

对不认代理变量的程序（Go 访问回环地址、自带根证书、容器），根本的解法是系统层的重定向（Linux 用 eBPF 或 nftables，macOS 用 Network Extension，Windows 用 WinDivert）。
这需要特权，每个平台各写一套，测试成本高，而且自带根证书的程序即使流量被重定向了也不会信任 httpmon 的证书。
v4.0 用 A 的独立代理加 `env`，覆盖"能配置代理但不是被 httpmon 启动"的那一大类；系统层拦截等 v4 稳定后单独评估。

---

## 第四部分：破坏性变更（不提供迁移）

| 变更 | 理由 |
|---|---|
| 模块路径 `…/v4`，`main` 移到 `cmd/httpmon`，`go install` 产物名为 `httpmon` | C |
| 删除 `--har`，改为 `query --format har` 导出 | D：一种捕获格式 |
| record 文件改为会话目录（`record.ndjson`、`state.json`、`meta.json`）；`--record FILE` 改为 `--session NAME`（或 `--session-dir PATH`） | A |
| `ca --dir` 合并进会话和配置体系：默认使用 `~/.config/httpmon/ca/`，`httpmon proxy` 自动使用它 | A |
| record 版本号升为 4（增加 `mocked`、`session_id`、实时状态需要的字段），**不再读取 v3** | B、A |

---

## 第五部分：发布节奏

| 版本 | 内容 |
|---|---|
| **v4.0.0** | A 独立代理 / 会话 / env / 实时状态；B mock、fault、map、`httpmon mock`；C 二进制名、校验和、来源证明、SBOM、安装脚本（sh / PowerShell）、容器镜像、三平台 CI（含安装脚本在 macOS 上的验证）、fuzz 和性能门；D grep、导出 curl 和 HAR；E 配置文件；F MCP |
| 以后 | macOS 签名和公证（如果以后有了 Apple Developer 账号）；包管理器渠道（如果以后决定建仓库） |
| v4.1 | 根据 v4.0 的使用反馈打磨规则语法；评估 G 系统层拦截 |

**维护者的决定（已确认）**：
1. 暂时没有 Apple Developer 账号：macOS 二进制不签名、不公证，改用安装脚本、`go install` 和容器镜像这些不受 Gatekeeper 隔离影响的方式交付（见 C）。
2. 不走 Homebrew：不新建 tap 仓库。Scoop bucket 同样需要新建仓库，一并不做。Windows 用 PowerShell 安装脚本和直接下载。

因此 v4.0 不依赖任何外部账号或新仓库，可以完全在这个仓库内完成。

一句话总结：v3 让 httpmon 成为"包装命令抓流量"这件事上最好的工具，而且对 agent 友好；
v4 要补齐顶级产品的三块基本盘——**任何来源都能接**、**能改流量**、**像产品一样交付**——
同时守住竞品没有的两点：零配置，以及为 agent 设计的接口。实测表明性能和健壮性已经不是问题，v4 的工作量集中在能力和工程化上。
