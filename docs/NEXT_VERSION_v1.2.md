# httpmon 下一个版本（v1.2.0）内容评估

基线：`v1.1.3`（main = `4e15ee4`）。83 个测试用例、`-race` 干净、golangci-lint 0 issues、
语句覆盖率 65.8%。

本轮评估的结论与 v1.1 那轮不同：**没有再靠读代码猜问题，而是先跑起来测**。
下面每一条都标了是实测结论还是代码走查结论。

---

## P0 — 流式传输被完全破坏（实测确认，双向）

这是 v1.2 唯一真正的头号项。

### 现象

**下行（SSE）** —— 服务端每 0.7s 推一条，共 5 条：

| | 事件到达时间 |
|---|---|
| 直连 | 36.846 / 37.546 / 38.247 / 38.948 / 39.649（逐条到达） |
| 经 httpmon | 44.434 / 44.437 / 44.439 / 44.440 / 44.443（**流结束后一次性到达**） |

用 time-to-first-byte 量化（3 条事件、间隔 2s 的端点）：

| | TTFB | 总耗时 |
|---|---|---|
| 直连 | **0.0245s** | 6.027s |
| 经 httpmon | **6.019s** | 6.020s |

首字节延迟被放大 **245 倍**，客户端在整个流结束前收不到任何东西。

**上行（chunked 上传）** —— 客户端每 1.5s 写 7 字节：

| | 服务端收到 |
|---|---|
| 直连 | 7 字节 @27.716、7 字节 @29.205、7 字节 @30.708 |
| 经 httpmon | **21 字节 @44.276（一次性）** |

### 根因

`main.go:618` 的 `peekBody`：

```go
func peekBody(body *io.ReadCloser, n int) []byte {
	buf := make([]byte, n)
	nr, _ := io.ReadFull(*body, buf)   // ← 阻塞直到读满 n 或 EOF
	...
}
```

`io.ReadFull` 只有在**读满 n 字节**或**流结束**时才返回。而 `renderBody` 的 peek 长度是
1000 字节（未压缩）或 1 MB（`--record` / `--har` / 压缩响应）。

流式响应几乎永远凑不满这个阈值，于是 httpmon 一直阻塞在 peek 上，
既不输出日志也不转发数据，直到上游把流关掉。请求侧走同一条路径，所以上传也一样被整体缓冲。

严重性在于这不是边角场景：SSE、long-polling、LLM token 流、`docker logs -f`、
`kubectl logs -f`、CI 日志流、大文件上传/下载的进度反馈，全部失效。
README 第一句写的是 "see every request and response in **real time**" ——
当前实现对流式内容恰恰做不到，而且是静默地做不到。

### 修复方向

需要把「先完整 peek，再记录，再转发」改成「边转发边采样」。建议：

1. **识别流式响应**，满足任一条件即进入流式路径：
   - `Content-Type` 为 `text/event-stream`
   - 响应无 `Content-Length`（chunked 或长度未知）
   - 请求体为 chunked（上行）
2. **流式路径改用 `io.TeeReader`**：先立即写出响应头并开始转发，
   同时把数据旁路进一个带上限（`--max-capture`）的采样缓冲。
3. **调整日志时序**：请求/响应头照旧立即输出；body 摘要在流结束或采样满时补一条。
   TUI 已经有 pending → 完成的条目更新机制（`tuiRespMsg`），可以直接复用；
   JSON 模式需要补一条 `body` 后续事件，text 模式在流结束后追加打印。
4. **非流式路径保持现状**，避免影响已验证的行为。

这是对日志管线的一次结构性调整，不是补丁，建议独占一个版本。

### 建议补的测试

- SSE 端到端：断言首字节在流结束**之前**到达（TTFB 显著小于总时长）。
- chunked 上传：断言服务端收到的是多次小写入而非一次大写入。
- 回归：非流式响应的 body 采样、截断标记、`--record` 内容均不变。

---

## P1 — 无法级联到上游代理（代码走查）

`newUpstreamClient`（`main.go:86`）构造的 `http.Transport` **没有设置 `Proxy` 字段**
（全文件 `Proxy:` 出现 0 次）。`http.Transport` 的零值 `Proxy` 是 nil，即完全不走代理；
而 `http.DefaultTransport` 用的是 `http.ProxyFromEnvironment`。

后果：在必须经公司代理/出网网关才能访问外网的环境里，httpmon 的上游请求会直连而失败。
这类环境恰恰是最需要抓包排查的场景。

注意时序是安全的：httpmon 只把 `HTTP_PROXY` 写进**子进程**的 env（`cmd.Env`），
自身进程读到的仍是外层代理，所以直接用 `ProxyFromEnvironment` 不会自环。

建议：`Proxy: http.ProxyFromEnvironment`，并加 `--upstream-proxy` 显式覆盖。
成本很低，建议纳入 v1.2。

---

## P1 — 测试有效性：回环测试会绕过代理（本轮踩到）

环境变量 `NO_PROXY` 普遍包含 `127.0.0.1`。curl 遵守它的优先级高于 `-x`，
所以**所有以 `https://127.0.0.1:port` 为目标、又没加 `--noproxy ''` 的测试，
实际上根本没有经过 httpmon**，却会显示通过。

v1.1.2 修掉的那个「HTTPS 请求挂死」的 bug 之所以能一路发布出去，
正是因为本地回环测试给了虚假的绿灯，只有打真实域名才暴露。

建议：
- 端到端测试统一显式 `--noproxy ''`，或改用非回环地址。
- CI 增加一个真正穿过代理的冒烟用例（现有 `startTestProxy` helper 已经具备条件，
  它用的是真实监听 + 真实 CONNECT，是可靠的；要小心的是外部 curl 场景）。

---

## P1 — HTTP/2 与 gRPC（原计划留给 v1.2）

现状未变：`ForceAttemptHTTP2` 未设、MITM 侧未通告 `h2`，所有流量降级为 HTTP/1.1，
gRPC 不可用。README 的 Limitations 已如实声明。

**建议推迟到 v1.3**，理由是它和 P0 的流式改造在同一片代码上：
h2 的多路复用会让当前「`#N` 顺序编号 + 一条连接一个请求循环」的模型失效，
TUI 的展示结构也要跟着改。先把流式管线理顺，再上 h2，返工会少很多。
两件事塞进同一个版本，风险不划算。

---

## P2 — 其余缺口

| 项 | 说明 |
|---|---|
| 明文 `ws://` 不支持 | 走 `handleHTTP`，`http.Client` 无法完成 101 升级。已在 README 声明 |
| `--har` 在 `--replay` 下无效 | 回放不启代理、不产生 HAR 条目。已声明 |
| `peekBody` 每请求分配 | `make([]byte, n+1)`，开启 `--record`/`--har` 时每请求 1 MB。流式改造顺带可以用有上限的增长缓冲替代 |
| TUI 渲染无法测 | `tui.go` 12 个函数平均覆盖 69%，`Update` 逻辑有覆盖，但 `View` 的实际渲染只断言了「不 panic」 |
| 覆盖率 65.8% | 未设门禁。流式改造后建议设一个不下降的基线 |

---

## 建议的 v1.2.0 范围

| # | 内容 | 类型 |
|---|------|------|
| P0 | 双向流式转发（TeeReader 采样 + 日志时序调整 + TUI/JSON 条目更新） | feat / fix |
| P1 | `Proxy: ProxyFromEnvironment` + `--upstream-proxy` | feat |
| P1 | 端到端测试显式绕开 `NO_PROXY`，补真实穿透代理的冒烟用例 | test |
| P2 | `peekBody` 改为有上限增长缓冲，去掉每请求固定分配 | perf |
| — | README：说明流式行为、上游代理支持 | docs |

**v1.3 再做**：HTTP/2 端到端 + gRPC 观测。

一句话总结：v1.1 那轮补齐的是「能看懂内容」（brotli/zstd、截断标记、安全默认值），
v1.2 要补的是「能实时看到」—— 目前这一点在流式场景下是完全不成立的，
而且失败方式是静默的，用户只会觉得"卡住了"。
