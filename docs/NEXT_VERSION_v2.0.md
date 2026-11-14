# httpmon v1.4.1 深度 review 与下一个大版本（v2.0.0）评估

基线：`v1.4.1`（main = `3679816`）。115 个测试函数、`-race` 干净、golangci-lint 0 issues、
语句覆盖率 71.8%（但 `run()` 在进程内为 0%，`binaryPlaceholder` 为 0%）。

和前几轮一样，每条结论都标注**实测**或**代码走查**。
实测方法：本地起 HTTP / HTTPS echo 服务（含 `:80` / `:443`，回显收到的 Host、全部请求头和 body），
分别直连和经 httpmon 比较；record / HAR / replay 用同一组服务端点验证。

本文分两部分：

1. **v1.4.1 现存缺陷**：大部分不需要破坏兼容就能修，建议先以 **v1.4.2** 发布。
2. **v2.0.0 评估**：哪些问题必须靠破坏性变更解决，2.0 该做什么、不该做什么。

---

## 第一部分：v1.4.1 review

### P0-1 响应 body 原样写进终端：服务端可以注入终端控制序列（实测）

文本模式和 TUI 把 body 原样输出到终端。`isPrintableContentType("")` 返回 true，
所以没有 `Content-Type` 的响应也会被当成文本打印。服务端返回下面这段 `text/plain`：

```
hello \x1b]0;PWNED-TITLE\x07\x1b[2J\x1b[31mred\x1b[0m \x1b]52;c;ZXZpbA==\x07 end
```

经 httpmon 后 stdout 里是原始字节（`cat -v`）：

```
hello ^[]0;PWNED-TITLE^G^[[2J^[[31mred^[[0m ^[]52;c;ZXZpbA==^G end
```

- `OSC 52` 会**写入用户剪贴板**（iTerm2、kitty、WezTerm、tmux 开了 `set-clipboard` 时都会生效）。
  恶意或被攻破的上游可以把一条命令塞进剪贴板，等用户粘贴；
- `CSI 2J` 清屏、`OSC 0` 改窗口标题，可以用来伪造或隐藏输出；
- httpmon 的定位就是"看不受信任的 HTTP 流量"，所以这个面是默认暴露的。

**修复**：所有写往终端的内容（body、header 值、URL、gRPC message）统一过一个 `sanitizeForTerminal`，
把 C0（保留 `\n` `\t`）、`ESC`、C1 和 `DEL` 转义成 `\x1b` 这种可见形式。
TUI 的 `renderEntryDetail` 也要过同一个函数。`--format json` 由 JSON 编码保证安全，不受影响；
record/HAR 保存原文，不需要处理。

### P0-2 HTTPS 请求发给上游的 Host 被改成 CONNECT 目标（实测）

| 场景 | 直连时服务端收到的 Host | 经 httpmon |
|---|---|---|
| `curl https://localhost/echo` | `localhost` | **`localhost:443`** |
| `curl -H 'Host: other.example' https://localhost/echo` | `other.example` | **`localhost:443`** |
| `curl -H 'Host: other.example' http://localhost/echo` | `other.example` | `localhost`（按 RFC 9112，代理以绝对 URI 为准，这一条没问题） |

**根因**：`handleTunnelRequest` 把 `r.URL.Host` 设成 CONNECT 目标（`host:443`），
`forwardRequest` 再用 `http.NewRequestWithContext(…, req.URL.String(), …)` 构造上游请求，
`proxyReq.Host` 就成了 URL 的 host，而客户端隧道内请求自己的 `Host` / `:authority` 被丢掉了。

**影响**：

- 所有 HTTPS 上游收到的都是 `Host: example.com:443`。服务端用 Host 拼出来的绝对 URL
  （重定向 `Location`、分页链接、OAuth 回调）会带上 `:443`；严格匹配虚拟主机的服务会 404 或 421；
- 隧道内 Host 和 CONNECT 目标不一致的请求（`curl --connect-to`、压测和灰度场景常用）被发到错误的虚拟主机；
- 显示、`--record`、HAR 里的 URL 都变成 `https://host:443/path`，和浏览器导出的 HAR 对不上。

**修复**：拨号用 CONNECT 目标，Host 用隧道内请求的 `r.Host`。也就是 `proxyReq.Host = req.Host`；
显示和记录用的 URL 由 `r.Host` 生成，去掉默认端口。加一个测试：经代理请求 `https://…:443`，
断言上游收到的 Host 不带端口，并且自定义的 `Host` 原样到达。

### P1-1 replay 处理二进制 body：请求被换成占位符，响应必然报 diff（实测）

record 存的是**显示用的视图**，不是原始字节。非文本 body 存成了 `"[binary data, 300+ bytes]"`。

- **请求侧**：`curl --data-binary @300字节.bin -H 'Content-Type: application/octet-stream'` 录下来，
  replay 时上游实际收到一个 **25 字节的 body**，也就是占位符字符串本身。replay 静默发出了错误的请求。
  v1.4.1 只给 gRPC 修过这个问题，其他二进制类型（protobuf over HTTP、文件上传、`application/x-amz-*`）都还在。
- **响应侧**：`decodeForCompare` 不会把二进制转成占位符，所以录下来的占位符和新响应的原始字节比较时**必然不等**。
  实测：一个返回 `application/octet-stream` 的端点，原样 replay 就报 `≠ changed`，
  `--replay-fail-on-diff` 退出码为 2。另外 "now:" 那一行把原始二进制直接打到终端（同 P0-1）。
- 同类问题（走查）：被截断的请求 body（`req_body_truncated`）照样重放，等于发出半个请求；
  带 `Content-Encoding` 的上传在 record 里存的是解码后的文本，replay 时却保留了 `Content-Encoding` 头。

**v1.4.2 修复**：请求 body 是占位符、被截断或带压缩时**跳过并说明原因**（复用 `Skipped`）；
响应侧先对新响应套用同样的 `decodeBody` 视图再比较。真正的修复要改 record 格式，放到 v2（见第二部分）。

### P1-2 失败的交换在所有输出里都丢失（实测 + 走查）

1.4.1 的主题是"不丢交换"，但只覆盖了成功的交换：

- **record**（实测）：4 个请求里 1 个上游连接被拒，record 文件只有 3 行。HAR 同理；
- **JSON**（走查）：`discardReqID` 之后不发任何事件，消费方只能看到孤立的 request 对象，无法判断失败还是还没完成；
- **TUI**（走查）：`discardReqID` 不通知 TUI，DNS 失败、证书校验失败、连接拒绝的条目**永远显示 pending**；
- **WebSocket**（走查）：`handleWebSocket` 记录请求后 `defer discardReqID`，从不调用 `logResponse`。
  所以文本模式只有 `=== REQUEST ===` 没有响应，TUI 条目永远 pending，record/HAR 里没有握手记录。
  README 写的 "upgrade handshake visible in TUI" 只对了一半。

**修复**：增加"失败"事件，三种输出都能收到。文本模式打 `=== RESPONSE #n FAILED: <err> ===`；
JSON 输出 `{"req_id":n,"error":"…"}`；TUI 标红显示错误；HAR 写 `status: 0` 加 `_error`
（Chrome DevTools 的写法）；record 加 `error` 字段，replay 跳过。
WebSocket 握手的 101 响应按普通响应记录，然后标记为 `upgraded`。

### P1-3 TUI 模式下有多处直接写 stderr，会把界面写花（走查）

`warnTLSVerification`、`handleConnect` 里的 `TLS handshake error` / `hijack error`、`relayOpaque` 失败，
都没有判断 `tuiMode`，直接写到 alt-screen 上。最容易触发的是**不信任 httpmon CA 的工具**：
JVM、自带根证书的二进制文件每次握手失败都会打一行，界面就乱了。
另外，启动横幅在 goroutine 里打印，只判断了 `!jsonMode`，TUI 模式下也会和 alt-screen 的初始化抢输出。

**修复**：TUI 模式下诊断信息改为 TUI 内的状态行或日志面板，退出后和 "Command Output" 一起打印到 stderr。

### P1-4 `--format json` 的输出和被包装命令的 stdout 混在一起（实测）

httpmon 的输出和子进程的 stdout 共用同一个 fd。实测
`httpmon --format json curl -s http://…/echo` 的 stdout 有 3 行：request、response，
再加上 **curl 自己打印的响应体**。README 里的示例
`httpmon --format json curl https://api.github.com | jq '.url'` 实际上会把 GitHub 的响应也喂给 jq；
如果响应是 HTML，jq 直接报错退出。文本模式下 `httpmon curl … > out.txt`，
out.txt 里也会混进横幅和全部抓包输出。

这个问题不破坏兼容就修不好，是 v2 的头号理由（见第二部分 §1）。v1.4.2 可以先加一个 `--output <file>`，不改默认行为。

### P2 其余问题

| # | 问题 | 依据 | 修复 |
|---|---|---|---|
| 1 | HAR 文件用 `os.Create` 建立，umask 022 下是 **0644**；record 是 0600。两者都含 `Authorization` 和 Cookie | 实测 | HAR 也用 0600 |
| 2 | 客户端没发 `Accept-Encoding` 时，Go Transport 自动加上 `gzip` 并透明解压，上游收到的请求和显示的不一致 | 实测 | `DisableCompression: true` |
| 3 | `Proxy-Connection` 透传到 HTTP/1.1 上游（`hopByHopHeaders` 里没有它） | 实测 | 加入剥离列表 |
| 4 | record 的 header 是 `map[string]string`：`Set-Cookie` 被合并成 `a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT, b=2`，无法还原；replay 用 `Header.Set` 发出合并后的值 | 实测 | v2 record 格式 |
| 5 | 向同一个 record 文件追加时 id 从 1 重新开始，replay 输出连续三个 `REPLAY #1` | 实测 | v2：会话 id + 序号 |
| 6 | header 和查询参数按 map 的随机顺序输出。TUI 每收到一个事件就重渲染详情，**header 顺序每次都在跳** | 走查 | 按名字排序，或保留线上顺序 |
| 7 | HAR 条目全部存在内存里，退出时才写盘：长时间运行内存一直涨；被 `kill -9` 或崩溃时全部丢失 | 走查 | 边抓边写，或者用临时文件，退出时合成 |
| 8 | 文本模式下压缩响应要缓冲最多 `--max-capture`（1 MB），再解压最多 10 MB，最后只显示 1000 字节 | 走查 | 显示路径只流式解压前 N 字节 |
| 9 | curl 参数检测只认独立的 `-x` / `--cacert`，漏掉了 `--proxy=…`、`-xURL`、`--cacert=…`、`-sk` 这类组合写法 | 走查 | 按前缀解析 |
| 10 | `go.mod` 还是 `go 1.24.2`。截至 2026-11，1.24 已出官方支持期（受支持的是 1.26 / 1.27） | — | v2 升到 1.26 |
| 11 | 所有状态都是包级全局变量（模式开关、`captures`、`harEntries`、`certCache`）。测试没法并行（全仓库只有 2 处 `t.Parallel`），`run()` 只能起子进程测，进程内覆盖率为 0 | 走查 | v2 重构（第二部分 §4） |

---

## 第二部分：为什么下一版应该是 2.0

v1.x 的五个版本修的都是"能不能抓到"。剩下的问题集中在**输出的契约**上：
输出写到哪里、record 存什么、终端里显示什么。这几处不破坏兼容就改不对，攒到一个大版本里一次性改掉最划算。

### §1 ⚠ 输出通道与子进程的 stdout 分开（破坏性）

- 默认把 httpmon 的输出（文本和 JSON）写到 **stderr**，子进程的 stdout 原样透传。这和 `strace`、`ltrace` 的约定一致；
- 新增 `-o, --output <file>`：写入文件（JSON 模式下用 `jq` 消费的标准做法）；
- `--output -` 显式写回 stdout，给依赖旧行为的脚本留一条迁移路径。

这样一来，`httpmon curl … | jq` 处理的是 curl 的输出，
`httpmon -o trace.ndjson --format json …` 拿到的是干净的 NDJSON，两种用法都成立。

### §2 ⚠ record 格式 v2（破坏性，replay 继续兼容读取 v1）

```json
{"v":2,"session":"01J…","seq":3,"time":"2026-11-14T01:58:18.123Z",
 "kind":"http","method":"POST","url":"https://api.example.com/up",
 "req_headers":[["Content-Type","application/octet-stream"],["Cookie","a=1"]],
 "req_body":{"encoding":"base64","data":"…","size":300,"truncated":false},
 "status":200,"resp_headers":[["Set-Cookie","a=1; Expires=…"],["Set-Cookie","b=2"]],
 "resp_body":{"encoding":"utf8","data":"…","size":1024,"truncated":false},
 "resp_trailers":[], "duration_ms":12, "error":null}
```

- header 用有序的 `[name, value]` 列表：多值和顺序都不丢，修 P2-4；
- body 存**线上原始字节**，文本用 utf8，其他用 base64。replay 能逐字节重发，修 P1-1；
  显示时再按 `Content-Encoding` 解码；
- `session` + `seq` 保证追加写入时不重复，修 P2-5；`error` 字段承接 P1-2；
- 时间精确到毫秒（v1 只到秒，同一秒内的多个请求排不出先后）；
- replay 能读 v1，碰到占位符或截断的 v1 条目时跳过并说明原因。

### §3 ⚠ 终端输出默认遮蔽凭据（破坏性，需要维护者拍板）

终端里的抓包输出最常见的去处是被**贴进 issue、聊天和 AI 对话**。建议在显示层（文本、JSON、TUI）
默认把 `Authorization`、`Proxy-Authorization`、`Cookie`、`Set-Cookie`、`X-Api-Key`、
`X-Amz-Security-Token` 遮蔽成 `Bearer eyJh…(812 chars)` 这种形式，用 `--show-secrets` 关闭遮蔽。
record 和 HAR 默认保留原文，因为 replay 需要；另提供 `--redact` 让它们也脱敏，方便分享 HAR。

这一条会改变用户已经习惯的默认行为，也是本文唯一需要维护者做产品取舍的地方。
如果不想改默认值，至少提供 `--redact`。

### §4 内部重构：交换事件模型（不影响用户，但后面的工作都依赖它）

现在每一种输出都在 `onRequestBody` / `onResponseBody` 里用 `if tuiMode … if jsonMode …` 分支处理，
新增一种失败路径（P1-2）、一种协议（WebSocket）或一个输出目标（`--output`、脱敏），都要改动所有分支。建议：

```
internal/ca        CA 与叶子证书、缓存、导出
internal/proxy     监听、CONNECT 分类、转发；不持有全局状态，配置通过 Proxy{} 传入
internal/capture   Exchange{ID, Kind(http|ws|tunnel), Req, Resp, Err, Frames}，按 ID 汇合
internal/sink      text / json / tui / record / har，各自订阅 Exchange 事件
internal/replay
main.go            只负责 flag 解析和子进程管理
```

收益：P1-2 和 P1-3 在这一层统一解决；`t.Parallel` 可以用起来；`run()` 能在进程内测试；
§1、§3 和下面的新能力都只是增加或修改一个 sink。

---

## v2.0 的新能力（按价值和成本排序）

| # | 能力 | 价值 | 成本 | 说明 |
|---|---|---|---|---|
| A | **JVM 接入 + 可持久化的 CA** | 高 | 中 | 这是 README Limitations 里最大的缺口（Gradle、Maven、sbt、Kotlin 和各类 Java SDK）。生成 PKCS#12 truststore，注入 `JAVA_TOOL_OPTIONS`（`-Djavax.net.ssl.trustStore=… -Dhttps.proxyHost/Port -Dhttp.nonProxyHosts=`，需要和继承来的值合并而不是覆盖）。同时提供 `httpmon ca export` 和 `--ca-dir`，让模拟器、容器、浏览器可以一次信任、长期使用 |
| B | **WebSocket 帧可见** | 高 | 中 | 现在升级之后就看不到内容了。解析帧，显示文本帧（含 `permessage-deflate` 解压）、二进制帧摘要和关闭码，TUI 里按连接分组显示。依赖 §4 的 `Exchange.Frames` |
| C | **TUI 实用性** | 中 | 中低 | `/` 搜索和过滤、失败条目标红（P1-2）、header 顺序固定（P2-6）、`c` 复制为 curl 命令、`e` 导出选中条目、条目数上限（环形缓冲，防止长时间运行占满内存） |
| D | **HAR 流式写入**、二进制 body 用 `encoding: base64` | 中 | 低 | 修 P2-7，并让导入 DevTools 后能看到真实 body，而不是占位符 |
| E | **gRPC 无 schema 解码**（类似 `protoc --decode_raw`） | 中 | 中 | 显示字段编号、类型和值；之后可以加 `--proto <descriptor set>`。可以放到 2.1 |

### 明确不放进 2.0

- 请求改写、断点、脚本（mitmproxy 的领域，会让工具失去"零配置包一层"的定位）；
- 浏览器 UI、系统级代理、透明代理；
- 自动给 Docker 容器注入（容器不继承环境变量，需要单独设计）。

---

## 建议的发布节奏

**v1.4.2（立即，全部兼容）**

| # | 内容 |
|---|------|
| P0-1 | 终端输出统一转义控制字符（文本、TUI、replay 的 "now:" 行） |
| P0-2 | 隧道内请求保留原始 Host，URL 去掉默认端口 |
| P1-1 | replay 跳过占位符、截断和压缩的请求 body；响应按显示视图比较 |
| P1-2 | 失败事件：文本、JSON、TUI、HAR（`status: 0`）、record（新增 `error` 字段，replay 跳过）；WebSocket 握手响应正常记录 |
| P1-3 | TUI 模式下不再直接写 stderr |
| P1-4 | 新增 `--output <file>`，默认行为不变 |
| P2 | HAR 用 0600；`DisableCompression`；剥离 `Proxy-Connection`；header 排序输出 |
| 测试 | 每一条都配回归测试：OSC 52 被转义、上游 Host 不带端口、二进制 body 的 replay、失败交换出现在 4 种输出里、HAR 权限 |

**v2.0.0**

| # | 内容 | 类型 |
|---|------|------|
| §1 | 输出默认写 stderr，`-o/--output`，`--output -` 兼容旧行为 | ⚠ breaking |
| §2 | record 格式 v2，replay 兼容读 v1 | ⚠ breaking |
| §3 | 显示层默认遮蔽凭据，`--show-secrets`，`--redact` | ⚠ breaking（待定） |
| §4 | `internal/` 重构 + 交换事件模型 | refactor |
| A | JVM 接入，`httpmon ca export`，`--ca-dir` | feat |
| B | WebSocket 帧可见 | feat |
| C | TUI 搜索、复制为 curl、导出、环形缓冲 | feat |
| D | HAR 流式写入，二进制用 base64 | feat |
| — | Go 1.26；README 增加 v1→v2 迁移说明（输出通道、record 格式、遮蔽） | chore / docs |

**v2.1**：gRPC 无 schema 解码，`--proto`。

一句话总结：v1.x 把"能抓到"做扎实了，但输出的契约还停留在 v1.0 的设计：
和子进程共用 stdout、record 存的是给人看的视图而不是原始字节、终端里原样回放不受信任的字节。
v1.4.2 先把能兼容修的漏洞补上（尤其是终端注入和 Host 改写），v2.0 的主题是**输出可组合、记录可还原、显示可分享**。
