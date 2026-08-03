# v1.1.0 施工计划

对应评估文档：`docs/NEXT_VERSION.md`。
本文只列**要做的具体事情**：每项给出改动文件、做法、测试、验收标准。

拆成 6 个 PR，PR-1 是其余项的前置依赖，PR-2..5 之间无依赖可并行。

---

## PR-1 · 退出路径重构（前置）

**问题**：`main` 以 `os.Exit` 结尾（`main.go:1004`、`main.go:1038`），
`defer os.Remove(caCertPath)`（`main.go:885`）与 `defer recordFile.Close()`（`main.go:858`）
从不执行 → 每次运行泄漏一个临时 CA bundle。
后续的 `--version`、HAR 写失败上报、`--insecure-upstream` 的 flag 时序都依赖这次重构。

**改动**

1. `main.go`：把 `main()` 主体抽为 `func run() int`，`main()` 只保留
   ```go
   func main() { os.Exit(run()) }
   ```
   所有 `os.Exit(code)` 改为 `return code`。
2. `run()` 内把 `log.Fatalf` 替换为 `fmt.Fprintf(os.Stderr, ...)` + `return 1`
   （三处：`main.go:856` 录制文件、`main.go:883` CA bundle、`main.go:889` 端口绑定）。
   `init()` 里的 `log.Fatal`（`main.go:67`、`main.go:86`）保留 —— 此时尚无待释放资源。
3. 新增集中清理：
   ```go
   var cleanups []func()
   func addCleanup(f func()) { cleanups = append(cleanups, f) }
   func runCleanups() { for i := len(cleanups)-1; i >= 0; i-- { cleanups[i]() } }
   ```
   `run()` 顶部 `defer runCleanups()`；CA bundle 与 record 文件改用 `addCleanup` 注册。
   用显式切片而非 `defer` 是为了让清理逻辑可被单元测试直接触发。
4. `writeHARFile` 的返回值不再丢弃（`main.go:1002`、`main.go:1036`）：
   ```go
   if err := writeHARFile(harPath); err != nil {
       fmt.Fprintf(os.Stderr, "httpmon: failed to write HAR file %s: %v\n", harPath, err)
       if exitCode == 0 { exitCode = 1 }
   }
   ```
   顺带删掉这两处的 `//nolint:errcheck`。

**测试**（`main_test.go`）
- `TestCleanups_RunInReverseOrder`：注册三个记录顺序的闭包，断言逆序执行。
- `TestCleanups_RemovesCABundle`：`buildCABundle` → `addCleanup(os.Remove)` → `runCleanups()`
  → 断言 `os.Stat` 返回 `IsNotExist`。
- 测试间需重置 `cleanups`，加 `t.Cleanup(func(){ cleanups = nil })`。

**验收**：`httpmon curl <url>` 结束后临时目录中无残留 `httpmon-ca-*.crt`；
HAR 写入失败时 stderr 有明确报错且退出码非 0。

---

## PR-2 · 压缩支持：brotli / zstd / 链式 / 截断容忍

**问题**（三条，均已实测确认）

1. `decompress.go:27` 的 `default` 分支对未知编码返回 `(data, nil)`。
   调用方 `main.go:311` / `main.go:441` 判断的是 `err == nil`，于是对
   `content-encoding: br` + `content-type: application/json` 的响应，
   **原始 brotli 字节被当作文本直接打印成乱码**（不是显示 `[br, N+ bytes]` 占位符）。
   实测：`decompressBody("br", raw)` → `err=<nil>, out==input`；
   `isPrintableContentType("application/json")` → `true`。
2. 同样的路径吃掉链式编码：`decompressBody("gzip, br", x)` 整串不匹配任何 case
   → 返回原始字节 + nil。
3. 压缩体超过 peek 上限（1 MB）时被截断，`io.ReadAll` 返回
   `unexpected EOF`，`decompressBody` 把**已经成功解出的部分一并丢弃**。
   实测：4 MB 随机数据 gzip 后 4195607 字节，截到 1 MB 时已可解出 1048246 字节，
   但当前实现直接判为失败，退化成 `[gzip, N+ bytes]`。

**改动**

1. 依赖：
   ```
   go get github.com/andybalholm/brotli
   go get github.com/klauspost/compress/zstd
   ```
2. `decompress.go` 重写为逐层解码：
   - 按 `,` 拆分 `Content-Encoding`，**逆序**依次解码（`gzip, br` 表示先 gzip 后 br，
     解码需先 br 再 gzip）。
   - 每层 `switch`：`gzip` / `deflate` / `br` / `zstd` / `identity`(直通)。
   - 未知编码 → 返回 `errUnsupportedEncoding`（新的 sentinel error），
     不再静默返回原始数据。
   - 截断容忍：把 `io.ReadAll` 换成手动读取，遇到
     `io.ErrUnexpectedEOF` / `io.EOF` / `flate.CorruptInputError` 时，
     **保留已解出的字节并返回 nil error**，同时通过新的返回值标记 `truncated bool`。
   - 保留 10 MiB 输出上限（`decompress.go:22`）。

   建议签名：
   ```go
   type decodeResult struct {
       Data      []byte
       Truncated bool // 因输入被截断或达到 10MiB 上限而不完整
   }
   func decompressBody(encoding string, data []byte) (decodeResult, error)
   ```
3. `main.go:308-318` 与 `main.go:438-448` 的分支同步调整：
   - 解码成功 → 用解出的文本；若 `Truncated` 则追加 `"\n… [truncated]"`。
   - 返回 `errUnsupportedEncoding` 或 content-type 不可打印 → 保持
     `[<enc>, N+ bytes]` 占位符。

**测试**（`main_test.go`，扩展现有 `TestDecompressBody_*`）
- `TestDecompressBody_Brotli` / `_Zstd`：往返。
- `TestDecompressBody_Chained`：`gzip(br(payload))` + `"br, gzip"` 头，断言还原。
- `TestDecompressBody_UnknownReturnsError`：`"snappy"` → `errUnsupportedEncoding`。
- `TestDecompressBody_TruncatedKeepsPrefix`：复现上面的 4 MB 用例，
  断言返回前缀非空、`Truncated==true`、`err==nil`。
- `TestLogResponse_BrotliNotGarbled`（回归）：构造 br 响应，
  断言输出**不等于**原始压缩字节。
- 更新 `TestDecompressBody_Identity` / `_Unknown` 以匹配新签名。

**验收**：`httpmon curl https://api.github.com/users/octocat`（GitHub 下发 br）
在终端显示可读 JSON。

---

## PR-3 · TUI 详情面板滚动

**问题**：`tui.go:89-120` 的 `case tea.KeyMsg:` 分支末尾无条件
`return m, nil`，`tui.go:158` 的 `m.vp.Update(msg)` 对按键永远不可达。
详情面板中超出高度的内容无法查看，也无任何提示。

**改动**（`tui.go`）

1. `Update` 的 `KeyMsg` 分支改为"消费即返回、未消费则透传"：
   ```go
   case tea.KeyMsg:
       switch msg.String() {
       case "q", "ctrl+c": return m, tea.Quit
       case "up", "k":     /* ... */ ; return m, nil
       case "down", "j":   /* ... */ ; return m, nil
       case "g", "G", "enter", " ", "esc": /* ... */ ; return m, nil
       }
       // 未被列表消费：详情面板打开时交给 viewport
       if m.showDetail {
           m.vp, vpCmd = m.vp.Update(msg)
       }
       return m, vpCmd
   ```
   这样 viewport 默认绑定的 `pgup` / `pgdown` / `ctrl+u` / `ctrl+d` /
   `home` / `end` 自动生效，且不与列表的 `j/k/g/G` 冲突。
2. 切换条目时把 viewport 滚回顶部：`refreshDetail()`（`tui.go:191`）
   在 `SetContent` 后调用 `m.vp.GotoTop()`。
   注意 `tuiRespMsg` 也会调 `refreshDetail`（`tui.go:150`），
   响应到达时不应把用户已滚动的位置重置 —— 给 `refreshDetail(resetScroll bool)` 加参数，
   仅光标移动时传 `true`。
3. 状态栏 hint（`tui.go:319`）在 `showDetail` 时改为包含
   `[pgup/pgdn] scroll`；面板未滚到底时在右下角显示 `▼`。

**测试**（新建 `tui_test.go`）
- `TestTUI_DetailScrolls`：`WindowSizeMsg{80,24}` → 灌入一条含 200 行 body 的
  `tuiReqMsg` → `KeyMsg("enter")` → 断言 `vp.YOffset==0`
  → `KeyMsg("pgdown")` → 断言 `vp.YOffset > 0`。
- `TestTUI_ListKeysNotSwallowedByViewport`：`j/k` 改变 `cursor` 且 `vp.YOffset` 不变。
- `TestTUI_CursorMoveResetsScroll`：滚动后按 `j`，断言 `YOffset` 归零。
- `TestTUI_ResponseDoesNotResetScroll`：滚动后送 `tuiRespMsg`，断言 `YOffset` 不变。
- `TestTUI_AutoFollow`：覆盖 `tui.go:134-137` 的自动跟随。

`Update` 是纯函数，直接构造 model 调用即可，无需真实终端。

---

## PR-4 · 上游 TLS 校验 + `--insecure-upstream`（破坏性变更）

**问题**：`main.go:72` 与 `main.go:756` 均为 `InsecureSkipVerify: true`，
上游证书完全不校验，被代理进程因此丧失了原有的证书校验能力。

**改动**

1. `main.go`：新增 flag
   ```go
   insecureFlag := flag.Bool("insecure-upstream", false,
       "skip TLS certificate verification for upstream servers")
   ```
2. `upstreamClient` 目前在 `init()` 构造（`main.go:70-80`），早于 `flag.Parse()`。
   抽出构造函数：
   ```go
   func newUpstreamClient(insecure bool) *http.Client
   ```
   `init()` 仍调用 `newUpstreamClient(false)` 以便现有测试直接可用；
   `run()` 在 `flag.Parse()` 之后按 flag 重新赋值。
   CA 生成留在 `init()` 不动（多个测试依赖）。
3. WebSocket 拨号（`main.go:756`）改为
   `&tls.Config{InsecureSkipVerify: insecureUpstream, ServerName: host}`。
   注意现在没有设 `ServerName`，依赖 `tls.Dial` 从 addr 推断；显式设置更稳妥。
4. 错误提示：`handleHTTP`（`main.go:652`）与 CONNECT 循环（`main.go:777`）
   在错误为 `*tls.CertificateVerificationError` 或 `x509.*Error` 时，
   在 stderr 追加一行：
   ```
   httpmon: upstream TLS verification failed for <host>; re-run with --insecure-upstream to bypass
   ```
   下游仍返回 502（行为不变）。
5. 现有测试 `TestHandleHTTP_ForwardsRequest` 等使用 `httptest.NewServer`（明文），不受影响；
   若有用 `NewTLSServer` 的需显式注入 insecure client。

**测试**
- `TestUpstream_TLSVerifiedByDefault`：`httptest.NewTLSServer`（自签名）
  + 默认 client → 断言 502 且响应体含 `x509` 或 `certificate`。
- `TestUpstream_InsecureFlagBypasses`：同一 server + `newUpstreamClient(true)` → 断言 200。
- `TestNewUpstreamClient_ConfigMatrix`：断言 `InsecureSkipVerify` 随参数变化。

**验收**：默认模式下代理一个自签名 HTTPS 站点会失败并给出可执行的提示；
加 `--insecure-upstream` 后成功。此变更须在 CHANGELOG 与 release notes 中单列。

---

## PR-5 · body 上限可配置 + 回放断言 + `--version`

三项互不相关的小改动，合并为一个 PR。

### 5a. `--max-body` / `--max-capture`

硬编码位置：`main.go:302-305`、`330-332`、`432-435`、`459-461`。

- 新增两个全局与 flag：
  ```go
  displayMaxBody = 1000    // --max-body,    展示上限
  captureMaxBody = 1 << 20 // --max-capture, 录制/HAR 上限
  ```
  peek 长度取 `max(displayMaxBody, captureMaxBody)`（仅当 record/HAR/压缩启用时用后者）。
- 截断时追加 `"… [truncated]"` 标记 —— 当前是**静默**截断（`main.go:330-332`），
  用户无法区分"body 就这么短"和"被截了"。
- 校验：两个值必须 > 0，`--max-capture` 不得小于 `--max-body`，否则报错退出。

> 不做 buffer 池化。`peekBody`（`main.go:507-513`）把 `buf` 交给
> `io.MultiReader` 长期持有，池化会引入 use-after-free 风险，
> 收益不值得。作为已知开销记入 README。

**测试**：`TestMaxBody_TruncationMarker`（设 `displayMaxBody=10`，断言含标记）；
`TestMaxCapture_RecordKeepsFullBody`（扩展现有 `TestRecord_LargeBodyFullyStored`）。

### 5b. `--replay-fail-on-diff`

`replayFile`（`record.go:96-144`）目前只在行解析失败时返回 1，
status/body 不一致仍返回 0，无法在 CI 做门禁。

- `replayOne`（`record.go:146`）改为返回结构体：
  ```go
  type replayResult struct {
      ID int; Method, URL string
      RecordedStatus, ActualStatus int
      StatusMatch, BodyMatch bool
      DurationMs int64
      Err string
  }
  ```
  打印逻辑保持不变，从结构体渲染。
- `replayFile` 累计 `diffs`；新增 flag `--replay-fail-on-diff`，
  为真且 `diffs > 0` 时返回 2（区别于解析错误的 1）。
- 汇总行加上 diff 计数：`replayed N request(s), M error(s), K diff(s)`。
- 顺带：`--format json` 复用到回放模式，每条结果输出一行 NDJSON
  （结构体已就位，成本极低）。

**测试**：httptest server 返回与录制不同的 status/body，
断言 `replayFile(..., failOnDiff=true)` 返回 2、`false` 时返回 0；
JSON 模式断言字段可解析。

### 5c. `--version`

- `main.go` 顶部 `var version = "dev"`；新增 `--version` flag，
  打印 `httpmon <version> (<runtime.Version()>, <GOOS>/<GOARCH>)` 并返回 0。
- `har.go:218` 的 `out.Log.Creator.Version = "1.0"` 改为 `version`。
- `.github/workflows/release.yml` 的 Build 步骤加：
  ```
  -ldflags="-s -w -X main.version=${{ steps.ver.outputs.tag }}"
  ```

**测试**：`TestHAR_CreatorVersion` 断言 HAR 中 creator.version == `version`。

---

## PR-6 · 工程基建与文档

### 6a. LICENSE
根目录补 `LICENSE`（MIT，与 README 声明一致）。当前缺失会让
pkg.go.dev 显示 "License: none"。

### 6b. CI 接入 golangci-lint
代码里已有 6 处 `//nolint:` 指令，但既无 `.golangci.yml` 也无 lint 步骤。

- 新增 `.golangci.yml`，启用 `errcheck, govet, staticcheck, ineffassign, unused, gosec, misspell`。
- `.github/workflows/ci.yml` 在 `go vet` 后加 `golangci-lint-action@v6`。
- 逐条复核现有 `//nolint`：`har.go:177` 的 `fmt.Sprintf("%s", statusText)` 是
  无意义包装，直接删；PR-1 已移除 `writeHARFile` 的两处。
- `go test` 加 `-coverprofile`，**先不设覆盖率门禁**，仅上传报告观察。

### 6c. 低成本顺带修复
- `har.go:171-188`：`content.size` 应为解压后大小、`bodySize` 应为传输字节数，
  当前两者都填截断后的 `len(body)`；`timings.send/receive` 恒为 0（至少标 `-1` 表示未知）。
- `main.go:151-152`：对 `api.github.com` 会多签一个无用的 `*.api.github.com`，
  且给每张 leaf 证书硬塞 `127.0.0.1`/`::1` IP SAN；host 为 IP 字面量时还会
  生成非法 DNSName。按 `net.ParseIP(host)` 分流。
- `tui.go:284-291`：用 `len()` 截断 URL/整行，多字节字符会被截半并破坏对齐，
  改用 `lipgloss.Width` + rune 感知截断。

### 6d. README
- Options 表补 `--insecure-upstream` / `--max-body` / `--max-capture` /
  `--replay-fail-on-diff` / `--version`。
- Security note 补充：默认校验上游证书、`--insecure-upstream` 的含义与风险。
- 压缩一节改写为 gzip / deflate / brotli / zstd + 链式编码。
- **新增 Limitations 章节**（当前完全缺失）：
  - 所有流量降级为 HTTP/1.1（未设 `ForceAttemptHTTP2`，MITM 侧未通告 `h2`）→ gRPC 不可用
  - 明文 `ws://` 不支持（走 `handleHTTP`，`http.Client` 无法完成 101 升级）
  - `--har` 在 `--replay` 模式下无效
  - body 展示/抓取上限及其内存开销
- 修正 "Everything is cleaned up when the command exits"（PR-1 后才成立）。

### 6e. CHANGELOG.md
新建，补写 v1.0.0–v1.0.2，v1.1.0 单独标注破坏性变更（PR-4）。

---

## 排期与顺序

```
PR-1 (退出路径)  ──┬─> PR-4 (TLS 校验，依赖 flag 时序重构)
                   ├─> PR-5 (max-body / replay / version)
                   └─> PR-6 (基建与文档，需汇总全部 flag)
PR-2 (压缩)      ── 独立
PR-3 (TUI 滚动)  ── 独立
```

建议合并顺序：PR-1 → PR-2 / PR-3（并行）→ PR-4 → PR-5 → PR-6 → 打 `v1.1.0`。

**发布前检查清单**
- [ ] `go vet` + `golangci-lint` 干净
- [ ] `go test -race -count=1` 全绿，新增用例覆盖上述每条修复
- [ ] 手工验证：运行后无 `httpmon-ca-*.crt` 残留
- [ ] 手工验证：br 响应显示为可读 JSON
- [ ] 手工验证：TUI 详情面板可翻页
- [ ] 手工验证：自签名上游默认被拒、`--insecure-upstream` 放行
- [ ] `--version` 输出携带 release tag（非 `dev`）
- [ ] CHANGELOG 标注 `--insecure-upstream` 默认值变更为破坏性变更

**不纳入 v1.1.0**：HTTP/2 端到端与 gRPC 观测。
它同时牵动 MITM 侧 ALPN 协商、上游 Transport 配置和 TUI 的展示模型
（h2 多路复用下 `#N` 顺序编号语义失效），需要独立设计，留到 v1.2。
