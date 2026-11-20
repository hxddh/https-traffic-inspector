# httpmon v4.1.0 评估与下一个大版本（v5.0.0）规划：全息可观测质变

> **状态**：已在 v5.0.0 实现（P0–P2 缺陷修复 + 五大可观测质变能力）。

基线：`v4.1.0`（main = `bddd8d5`，已发布）。在 `linux/arm64`（Go 1.26.11）上完成全量代码走查与发布二进制实测。

**设计目标**：把所有安全/正确性修复与下一代深度可观测能力合并到 **v5.0.0** 一次性交付，实现从「扁平 HTTP 报文记录器 + 规则代理」到**「全息因果可观测引擎」**的质变，同时严守三条铁律：
1. **保持简洁易用、使用不复杂化**：零新增必选参数、零新增顶级子命令、零外部新依赖；
2. **可观测内容极其丰富**：连接阶段瀑布、TLS/证书细节、SSE/LLM 流重组、HTTP-200 软错误、隧道盲区入库、零泄密鉴权/Multipart/CORS 语义、跨请求因果链全部自动采集；
3. **极致 Agent 友好**：「全息采集 · 分层显影 · 异常自浮现」——健康请求在 `summary` 中一字不增，异常请求自动浮现根因标签，按需展开（`query --id` / `--diagnose` / MCP `diagnose_session`）获得全息诊断。

---

## 第一部分：v4.1.0 深度走查与实测问题

| 级别 | 问题 | 依据 | v5.0.0 修复 |
|---|---|---|---|
| **P0 安全** | 项目级 `.httpmon.toml` 允许 `mock = ["* => 200 @/etc/passwd"]` 越权读取任意本地文件，允许 `mock_from` 引用外部会话，且 `header` 敏感头仅拦截 3 个（漏掉 `X-Api-Key` 等 10 个），`httpmon proxy` 也会隐式读取当前工作目录的 `.httpmon.toml` | 实测 + 走查（`config.go:87`、`rules.go:235`） | 项目配置禁用 `mock_from`；`@FILE` 解析并经 `EvalSymlinks` 严格限制在项目目录内；敏感头校验复用 `textsafe.IsSensitiveHeader`；`httpmon proxy` 仅加载用户级 `config.toml` |
| **P1 MCP** | `httpmon mcp` 单协程同步执行工具，`wait_for_exchange` 最长阻塞 stdin 60s（实测连带卡死并发 `ping`，且无法响应 `notifications/cancelled`）；`get_exchange` 改写全局变量 `displayMaxBody` 污染后续调用；`diff_sessions` 忽略 `.httpmon.toml` 的 `ignore` 且无 `ignore` 参数；`query_exchanges` 缺 `rule` 过滤 | 实测 + 走查（`mcp.go:97,430,489`） | 异步并发请求分发 + 支持 `notifications/cancelled` 取消等待；消除全局 `displayMaxBody` / `textOut` 污染；补齐 `ignore`、`rule` 参数并新增 `diagnose_session` |
| **P1 规则** | 规则 `PATTERN` 带查询串（如 `GET host/items?page=2 => 500`）解析零报错，但 `Decide` 仅传 `req.URL.Path`，导致 100% 静默不命中 | 实测 + 走查（`rules.go:206`） | 规则含 `?` 时匹配 `path?query`，不含 `?` 时仍匹配 `path` |
| **P1 会话** | `Meta.Running()` 仅调用 `kill(pid, 0)`，未核对 `live.json` 心跳；容器内 `PID 1` 或宿主机 PID 复用后，崩溃会话永久显示 `running` 且无法 `sessions rm` / `prune` | 实测 + 走查（`session.go:156`） | 结合 `live.json` 心跳时间戳判定存活，解决容器与崩溃后死锁 |
| **P1 契约** | `httpmon schema` 漏掉 `"rule"` 字段，且无单测防止 Schema 与 `Exchange` 结构体漂移 | 实测 + 走查（`agents.go:157`） | 升级为 Exchange Schema v4，补齐全部字段并加入结构体字段自动对账测试 |
| **P2 耗时** | `responseFacts` 已测出响应头耗时（TTFB）却在 `buildExchange` 中丢弃，HAR `timings.wait` 把流下载总时长错算为等待时长 | 实测 + 走查（`record.go:59`、`har.go:146`） | 引入 `httptrace` 6 阶段耗时拆分，精确填充 `Exchange.Timings` 与 HAR 1.2 `timings` |
| **P2 编码** | `query.go`、`mcp.go`、`record.go` 多处对字符串按字节下标硬切，可能劈开多字节 UTF-8 字符；截断的大 JSON 完全跳过 `ErrorHint` 提取 | 走查 | 统一使用 `textsafe.ClipUTF8` 按 rune 边界裁剪；截断 JSON 前缀支持容错提取 `ErrorHint` |
| **P2 一致性** | `httpmon ui` 按 `r` 重放未复用 `replay.go` 的空包体与 `h2c` 逻辑；`release.yml` 手动重发旧 tag 时 `release`/`container` 任务未切回 tag | 走查 | 统一重放发送实现；修正 `release.yml` 的 `ref` 检出逻辑 |

---

## 第二部分：v5.0.0 五大可观测质变

### 1. 流式与 AI 协议全息解码 + HTTP-200 软错误浮现
- **SSE（`text/event-stream`）与 NDJSON（`application/x-ndjson` / `application/jsonl`）原生解析**：
  - 自动统计事件数、首包/首帧耗时（`ttft_ms`）；
  - **首尾双保 + 错误帧锚定截断**：超预算时保留开头帧、结尾帧（含 `usage` / `stop_reason`）及所有 `error` 帧，绝不再把流尾部的报错和用量截丢；
  - **LLM 流智能重组**：自动识别 OpenAI / Anthropic / Gemini 流式响应结构，拼合 `assembled` 文本、工具调用名（`tool_calls`）、模型名与 `usage` 统计。
- **HTTP-200 软错误（`app_error`）一等公民化**：
  - 自动识别 **SSE 中途错误帧**、**GraphQL `200` 非空 `errors[]`**、**JSON-RPC `200` `"error"` 对象**，写入 `Exchange.AppError` 并在摘要行直接显示原因；
  - `--fail-on` 新增 `app_error`（同时覆盖上述软错误与非 0 的 gRPC 状态码）。

### 2. 网络与 TLS 全链路显微镜（零依赖 `httptrace`）
- 每个上游请求自动采集 `timings: {dns_ms, tcp_ms, tls_ms, send_ms, wait_ms, recv_ms}` 与 `conn: {id, reused, remote_addr, alpn, tls_version, cipher_suite, cert_subject, cert_issuer, cert_days_left}`；
- 慢请求若由 DNS 或 TLS 握手主导，`summary` 自动内联瓶颈提示；`query --id` 与 TUI 展示完整阶段瀑布与连接复用状态；HAR 导出完整填充 `dns`、`connect`、`ssl`、`send`、`wait`、`receive`、`serverIPAddress`、`connection`。

### 3. 消除隧道盲区：客户端拒信 CA 与非 HTTP 隧道入库
- 客户端在 `CONNECT` 后拒绝信任 `httpmon` CA（TLS 握手失败）时，生成 `kind: "connect"`、`error.kind: "client_tls_untrusted"` 记录写入会话，不再只在控制台打一行稍纵即逝的提示；
- 非 HTTP 隧道盲中继（数据库、SSH 等）结束时记录 `kind: "tunnel"` 及上下行字节数（`bytes_up`、`bytes_down`），让 Agent 通过 `query` 或 `mcp` 一眼看清全局网络行为。

### 4. 零泄密 HTTP 语义 X 光片
- **Multipart 表单解剖**：利用标准库 `mime/multipart` 将 `multipart/form-data` 解析为结构化 `parts[]`（字段名、文件名、Content-Type、字节数、文本预览）；
- **安全鉴权透视（绝不暴露密钥原文）**：脱敏同时提取 JWT 非敏感元数据（`alg`、`iss`、`sub`、`exp`、**是否已过期**）与 AWS SigV4 的 `region`/`service`；401/403 遇到过期 JWT 时摘要行直接标注 `jwt_expired`；
- **限流 / 缓存 / CORS 归一化诊断**：自动提取 `RateLimit` / `Retry-After`、缓存命中状态（`HIT`/`MISS`/`304`），以及浏览器 CORS 预检与响应头不匹配的具体原因（如 `Allow-Origin: *` 配合 `Allow-Credentials: true` 或缺失允许头）。

### 5. 跨请求因果引擎与一键会话诊断
- 自动关联**重定向链**（`redirect_from`）并检测**跨域重定向剥离 `Authorization` 头**；
- 自动关联**重试链**（`retry_of`、`attempt`）；
- 运行结束 `Digest` 自动归纳跨请求异常洞察（`insights`：跨域重定向丢鉴权、重试风暴耗时、同域名连接池零复用、疑似 N+1 串行请求簇、CORS 失败、过期 JWT）；
- `httpmon query <session> --diagnose` 与 MCP `diagnose_session` 提供一屏式全息病因报告。

---

## 第三部分：兼容性与迁移说明

- Go 模块路径升级为 `github.com/hxddh/https-traffic-inspector/v5`（安装命令：`go install github.com/hxddh/https-traffic-inspector/v5/cmd/httpmon@latest`）；
- 会话记录格式升至 `v: 4`，**向后兼容读取 `v: 3`（v4.x 会话可直接被 v5.0 `query` / `diff` / `replay` / `mcp` 读取）**；
- 现有 CLI 子命令与参数完全兼容；项目级 `.httpmon.toml` 因安全收紧不再允许 `mock_from`、越界 `@FILE` 及设置任意凭据请求头。
