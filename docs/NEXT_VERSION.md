# httpmon 下一个版本（v1.1.0）内容评估

本文基于对 `v1.0.2` 代码与 README 的完整走查，列出下一个版本建议纳入的内容。
每一条都标注了依据（文件:行）与优先级。

现状基线：36 个测试用例全部通过，`go vet` 干净；功能面已覆盖
MITM 代理 / 过滤 / JSON 输出 / TUI / 录制回放 / HAR / gzip-deflate 解压 / WebSocket。

---

## P0 — 正确性与"文档与实现不符"

### 1. 临时 CA bundle 文件每次运行都泄漏

`main.go:885` 用 `defer os.Remove(caCertPath)` 清理，但 `main` 结尾走的是
`os.Exit(code)`（`main.go:1004`、`main.go:1038`），`os.Exit` 不执行 defer。
结果：每次运行都会在临时目录留下一个 `httpmon-ca-*.crt`。
同理 `defer recordFile.Close()`（`main.go:858`）也不会执行。

README "How it works" 一节写的 **"Everything is cleaned up when the command exits."**
目前不成立。

修法：把退出逻辑收敛成 `run() int` + `main` 里 `os.Exit(run())`，
或显式 cleanup 函数在每个退出路径调用。

### 2. TUI 详情面板无法滚动

`tui.go:89-120` 的 `case tea.KeyMsg:` 分支在 switch 之后无条件
`return m, nil`，因此 `tui.go:158` 的 `m.vp.Update(msg)` 对按键事件永远不可达。
viewport 收不到任何按键 → 详情面板里超过面板高度的 body/headers 完全看不到，
且没有任何提示。这是 `--ui` 的核心可用性缺陷。

修法：在 `showDetail` 为真时把未被列表消费的按键透传给 viewport，
并为详情面板单独绑定翻页键（如 `PgUp/PgDn`、`ctrl+u/ctrl+d`）。

### 3. 上游 TLS 完全不校验，且未在文档中说明

`main.go:72` 与 `main.go:756` 都是 `InsecureSkipVerify: true`。
即 httpmon 对**上游服务端证书不做任何校验**，被代理的进程因此失去了它本来
拥有的证书校验能力（它只校验到 httpmon 这一跳）。

README 的 Security note 只说明了"CA 私钥不落盘"，没有提这一点。
这是调试工具的合理默认，但必须写清楚，并给出开关。

建议：新增 `--insecure-upstream`（默认 `false`，即默认校验上游），
校验失败时向下游返回 502 并打印明确原因；README Security note 补充说明。

### 4. 缺少 LICENSE 文件

README 声明 MIT，但仓库根目录没有 `LICENSE`。
pkg.go.dev 与 `go install` 场景下会显示为 "License: none"，影响可采用性。
补一个 MIT LICENSE 文件即可。

---

## P1 — 功能缺口（决定"能不能用在真实流量上"）

### 5. Brotli / Zstd 解压

`decompress.go:15-29` 只支持 gzip 和 deflate。
但 Cloudflare、GitHub、绝大多数现代 CDN 默认下发 `content-encoding: br`，
Chrome/curl 也已普遍协商 `zstd`。当前这些响应会退化成
`[br, N+ bytes]`（`main.go:444`），也就是最常见的 HTTPS API 反而看不到 body。

这是当前版本"body 可读性"最大的实际漏洞，建议列为 v1.1 的头号特性。
实现上需引入 `github.com/andybalholm/brotli` 和 `github.com/klauspost/compress/zstd`
（后者同时可替换 flate 实现）。

### 6. 上游不走 HTTP/2

`main.go:71-76` 自定义了 `TLSClientConfig` 但没有设置 `ForceAttemptHTTP2`，
Go 在这种情况下**不会**自动启用 HTTP/2；同时 MITM 的 leaf 证书 TLS 配置
（`main.go:700-702`）没有在 `NextProtos` 里通告 `h2`。

净效果：所有经过 httpmon 的流量都被降级成 HTTP/1.1。对多数 REST API 无影响，
但会改变被观测程序的真实行为，且 gRPC 客户端直接不可用。

建议：至少在 README 中明确声明"当前一律降级为 HTTP/1.1"，
并把 h2 端到端支持作为 v1.1 或 v1.2 的目标。

### 7. body 截断长度不可配置

1 KB 展示上限与 1 MB 录制上限都是硬编码（`main.go:302-305`、`main.go:330-332`、
`main.go:432-435`、`main.go:459-461`）。
调试大 JSON 响应时 1 KB 太小，抓大文件时 1 MB 的 `make([]byte, n)` 又是
每请求一次的固定分配。

建议：新增 `--max-body`（展示上限，默认 1KB）与 `--max-capture`
（录制/HAR 上限，默认 1MB），并复用缓冲区。

### 8. 回放无法用于 CI 断言

`record.go:96-144` 的 `replayFile` 只在**行解析失败**时返回 1；
status 不匹配、body 变化都只打印，退出码仍是 0。
README 把回放定位为 "regression testing"，但当前无法在 CI 里作为门禁使用。

建议：新增 `--replay-fail-on-diff`（status 或 body 不一致即以非 0 退出），
并输出一行机器可读的汇总（如 `--format json` 复用到回放模式）。

### 9. 过滤能力偏弱

`matchesFilter`（`main.go:224-232`）只有大小写不敏感的子串匹配。
建议扩展：`--filter-method GET,POST`、`--filter-status 4xx,5xx`、
以及 `--filter-re` 正则。状态码过滤需要把过滤时机从请求侧下移到响应侧
（当前 CONNECT 循环 `main.go:747` 在请求阶段就决定了 shouldLog）。

---

## P2 — 质量与工程化

### 10. HAR 输出的字段精度与错误吞掉

- `har.go:171` 用截断/解压后的 `len(body)` 同时填 `content.size` 和 `bodySize`；
  按 HAR 1.2，`content.size` 应为解压后大小，`bodySize` 应为实际传输字节数。
- `har.go:189` 只填了 `timings.wait`，`send`/`receive` 恒为 0。
- `har.go:177` 的 `fmt.Sprintf("%s", statusText)` 是多余的。
- `writeHARFile` 的错误在 `main.go:1002` 和 `main.go:1036` 被 `//nolint:errcheck`
  丢弃 —— HAR 写失败时用户完全没有感知。至少应打到 stderr。
- 回放模式（`main.go:842-844`）直接 `os.Exit`，`--har` 在回放时无效，未在文档中说明。

### 11. 证书 SAN 生成有冗余

`main.go:151-152`：对 `api.github.com` 会额外签发 `*.api.github.com`（无意义），
并且给每张 leaf 证书都塞入 `127.0.0.1` / `::1` 的 IP SAN；
当 CONNECT 目标本身是 IP 字面量时，会生成一个非法的 DNSName。
建议按 host 是否为 IP 分流，只在需要时加 IP SAN。

### 12. TUI 列宽按字节计算

`tui.go:284-291` 用 `len()` 截断 URL 和整行，对含多字节字符的 URL 会截出
半个字符并破坏对齐。应改用 `lipgloss.Width` / rune 感知的截断。

### 13. 工程基建缺失

- CI（`.github/workflows/ci.yml`）只有 `go vet` + `go test -race`；
  代码里已有多处 `//nolint:` 指令，说明本来就打算上 golangci-lint，但没有配置文件也没有该步骤。
- 无 `CHANGELOG.md`，三个 release 全靠 `generate_release_notes` 自动生成。
- `--version` 标志不存在，发布二进制无法自证版本；`har.go:218` 的
  `Creator.Version` 还硬编码为 `"1.0"`。
  建议用 `-ldflags "-X main.version=..."` 在 release workflow 注入，并加 `--version`。
- `tui.go` 基本没有测试覆盖（36 个用例里 0 个针对 TUI model）。
  Bubble Tea 的 `Update` 是纯函数，很容易加表驱动测试 —— 上面第 2 条那种 bug
  正是因为缺这层覆盖才漏掉的。

### 14. ws:// （明文）不被支持

README 的 WebSocket 一节只承诺 `wss://`。实际上明文 `ws://` 走的是
`handleHTTP`（`main.go:596`），用 `http.Client` 转发，无法完成 101 升级，
连接会失败。要么支持，要么在 README 里显式写明不支持。

---

## 建议的 v1.1.0 范围

一个偏小、可在一个迭代内完成且能显著提升实用性的组合：

| # | 内容 | 类型 |
|---|------|------|
| 1 | 修复临时 CA 文件泄漏与退出路径 defer | fix |
| 2 | 修复 TUI 详情面板无法滚动 | fix |
| 5 | brotli / zstd 解压 | feat |
| 3 | `--insecure-upstream`，默认校验上游 TLS | feat（行为变更） |
| 7 | `--max-body` / `--max-capture` | feat |
| 8 | `--replay-fail-on-diff` | feat |
| — | `--version` + ldflags 注入 + HAR creator version | feat |
| 4 | 补 LICENSE | chore |
| 13 | golangci-lint 接入 CI + TUI model 测试 | chore |
| — | README：上游 TLS 校验、HTTP/1.1 降级、ws:// 限制、清理行为 | docs |

第 3 项默认值的改变（从"不校验"到"校验"）是唯一的破坏性变更，
应在 CHANGELOG 与 release notes 中单独标注。

HTTP/2 端到端（第 6 项）与 gRPC 观测建议留到 v1.2，
因为它同时牵动 MITM 侧 ALPN 协商、上游 Transport 和 TUI 的展示模型，
不适合和上面这批一起做。
