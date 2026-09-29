# httpmon 下一个版本（v1.3.0）内容评估

基线：`v1.2.1`（main = `30ec488`）。88 个测试函数、`-race` 干净、golangci-lint 0 issues、
语句覆盖率 66.6%。

和 v1.2 那轮一样，结论以实测为主，每条都标了是**实测**还是**代码走查**。
测试方法：本地起一个打印 `Transfer-Encoding` / `Content-Length` 的 echo 服务器（HTTP + HTTPS），
分别直连和经 httpmon 比较；必要时用 v1.1.3（`4e15ee4`）的构建做回归对照。

---

## P0 — v1.2.0 回归：空 body 请求被改成 `Transfer-Encoding: chunked`（实测）

### 现象

| 请求 | 直连，服务端看到 | v1.1.3 | **v1.2.1** |
|---|---|---|---|
| `curl -X POST -d ""`（`Content-Length: 0`） | `CL=0` | `CL=0` | **`TE=chunked`** |
| `curl -X PUT -H 'Content-Length: 0'` | `CL=0` | — | **`TE=chunked`** |
| `curl -X POST`（无 body、无 CL） | 均无 | 均无 | **`TE=chunked`** |
| `curl -X POST -d hello` | `CL=5` | `CL=5` | `CL=5`（正常） |

HTTP 路径和 CONNECT（HTTPS）路径都复现。

### 根因

`net/http` 对空 body 的请求把 `Body` 设为 `http.NoBody`。v1.2.0 的 `sampleBody`
（`stream.go:84`）无条件把它包成 `*bodySampler`。之后 `Request.outgoingLength()`
的判断是：

```go
if r.Body == nil || r.Body == NoBody { return 0 }
if r.ContentLength != 0 { return r.ContentLength }
return -1   // ← 包装后的 NoBody 落到这里：长度"未知"
```

长度未知 + POST/PUT ⇒ Transport 改用 chunked 发送。

### 为什么是 P0

- **S3 是 README 的头号示例**，而 S3 对带 `Transfer-Encoding` 的请求返回
  `501 NotImplemented`。`CreateMultipartUpload`（`POST ?uploads`）、各种空 body 的
  `PUT`（复制对象、打 tag 的部分场景）都是 CL=0 请求 —— 用 httpmon 包 `aws s3 cp`
  大文件会在第一步就失败。
- 同类问题：部分网关/WAF、老版本服务端对 chunked 请求返回 411。
- 失败方式**不静默**但很误导：用户看到的是服务端报错，自然会怀疑自己的命令而不是 httpmon。

### 修复

`sampleBody` 遇到 `nil` 或 `http.NoBody` 时直接回调 `onDone(bodyView{})`、不替换 body。
两行改动。补一个测试：经代理发 CL=0 的 POST/PUT，断言上游收到 `Content-Length: 0`
且没有 `Transfer-Encoding`。

**建议立即以 v1.2.2 单独发布**，不等 v1.3。

---

## P0 — 代理监听在所有网卡上，局域网可借道访问本机服务（实测）

`main.go:1130`：`net.Listen("tcp", ":"+port)` 绑定的是 `0.0.0.0`，默认端口 8080。

实测：httpmon 运行期间，从非回环地址 `192.0.2.2:18099` 把它当代理，请求
`http://127.0.0.1:18081/` —— **成功拿到本机回环服务的响应**。

也就是说，只要 httpmon 在跑，同一网络里任何人都可以：

- 把它当**开放代理**使用；
- 经它访问用户**只监听在 127.0.0.1 的服务**（本地数据库管理界面、dev server、
  云 metadata 转发、Jupyter 等），等同于把这些服务暴露给局域网；
- 这些流量还会被记进用户的 `--record` / `--har` 文件。

在咖啡馆 Wi-Fi 或共享办公网络里跑一次 `httpmon aws ...` 就足够了。

### 修复

- 默认绑定 `127.0.0.1`；注入子进程的代理地址同步从 `localhost` 改为 `127.0.0.1`
  （避免 `localhost` 解析到 `::1` 而连不上）。
- 新增 `--listen <addr>`（例如 `--listen 0.0.0.0:8080`）供需要从容器/虚拟机接入的场景显式放开，
  放开时在 stderr 打一行警告。
- CHANGELOG 标为 ⚠ Breaking（依赖跨机访问的用户需要加参数）。

顺带建议：默认端口从 `8080` 改为 `0`（随机空闲端口）。8080 是最常被本地 dev server
占用的端口，冲突时 httpmon 直接退出；子进程拿到的地址本来就是注入的，固定端口没有收益。

---

## P1 — 文本模式下并发请求的响应无法对应（实测）

`logResponse` 打印 `=== RESPONSE ===`，`onResponseBody` 打印 `Body:`，**都不带请求编号**；
而且每一行是独立的 `fmt.Printf`，没有锁。`curl -Z` 并发 4 个请求的实际输出：

```
=== REQUEST #1 ===
=== RESPONSE ===
Body:
=== REQUEST #2 ===
=== REQUEST #3 ===
=== REQUEST #4 ===
=== RESPONSE ===
=== RESPONSE ===
Body:
=== RESPONSE ===
Body:
Body:
```

后三个响应和后三个 body 各属于哪个请求，从输出上**无法判断**。
v1.2.0 让 body 延后到流结束才打印，使得这个问题从"偶尔交错"变成了"并发时必然错位"。
`npm install`、`pip install`、`aws s3 sync` 这类默认并发的工具全部受影响。

### 修复

- 响应头和 body 块都带编号：`=== RESPONSE #3 (200, 142ms) ===`、`--- RESPONSE #3 body ---`。
- 每个块先拼成一个字符串，再在一把输出锁下一次写出，保证块内不交错。
- JSON 和 TUI 已按 ID 关联，不受影响。

---

## P1 — 常见工具没有被接入（实测）

httpmon 注入的变量是 `HTTP(S)_PROXY`、`REQUESTS_CA_BUNDLE`、`SSL_CERT_FILE`、
`NODE_EXTRA_CA_CERTS`（`aws` 额外加 `AWS_CA_BUNDLE`）。实测缺口：

| 工具 | 结果 | 原因 | 修复 |
|---|---|---|---|
| `git` (https) | `server certificate verification failed. CAfile: none` | git 的 libcurl 不读 `SSL_CERT_FILE` | 注入 `GIT_SSL_CAINFO` |
| `node` 22 内置 `fetch` | **完全绕过 httpmon**，一条请求都没抓到 | undici 默认不读 `HTTP(S)_PROXY` | 注入 `NODE_USE_ENV_PROXY=1`（Node ≥ 22.21 / 24 支持；实测加上后能抓到） |
| 子进程里间接调用的 `curl` | 用户环境若设了 `CURL_CA_BUNDLE` 会覆盖 | 只对顶层 `curl` 改写了参数 | 注入 `CURL_CA_BUNDLE` |
| 用户环境已有 `GIT_SSL_CAINFO` 等 | 继承值优先，校验失败 | 同上 | 注入时覆盖 |

`node` 这一条最严重：现在 Node 生态主流 HTTP 客户端就是内置 `fetch`，而失败方式是**静默**的 ——
命令成功、httpmon 什么都不打印，和 v1.2.1 修的 `NO_PROXY` 问题是同一类。

走查补充（未实测，建议一并加）：`CARGO_HTTP_CAINFO`（cargo）、`PIP_CERT`（与
`REQUESTS_CA_BUNDLE` 冗余但更稳）、`DENO_CERT`。Java 需要 truststore，成本高，写进 Limitations 即可。

---

## P1 — `--upstream-proxy` 只覆盖了一半的出站路径（replay 实测、WSS 走查）

v1.2.0 给主代理路径加了上游代理支持，但另外两条出站路径没跟上 ——
和 v1.1.3 修过的 "`--insecure-upstream` 不作用于 replay" 是同一个模式：

- **replay**：`replayFile`（`record.go:130`）自己 new 了一个 `http.Transport`，`Proxy` 为 nil。
  实测：`--upstream-proxy http://127.0.0.1:1` 下，代理模式立即 502（`connection refused`，说明确实走了），
  而 `--replay` 照样直连成功 —— 在必须经出网代理的环境里 replay 会直接失败。
- **WSS**：`handleConnect` 用 `tls.Dial("tcp", r.Host, …)` 直连上游，同样绕过上游代理。

### 修复

把 Transport 构造收敛到一个函数（`newUpstreamTransport(insecure)`），
代理、replay、WebSocket 拨号共用：WSS 拨号改为按 `Proxy` 函数的结果先发 `CONNECT` 再 TLS。
再加一个测试：设置不可达的 `--upstream-proxy`，三条路径都必须失败。

---

## P2 — 记录完整性（代码走查）

| 项 | 说明 |
|---|---|
| 早响应丢记录 | `--record`/`--har` 的响应条目要求请求 body 回调**先**完成（`pendingRecords[reqID]`）。服务端在读完上传前就回响应（413、鉴权失败、流式双向）时，响应先到，查不到 pending 条目，整条交换被静默丢弃 |
| pending 泄漏 | 上游 `Do` 失败时先 `discardReqID`，之后 Transport 关闭请求 body 又触发回调，把条目重新写回 `pendingRecords`/`pendingHAR`，永不清理。量小，但长时间运行会累积 |
| 中断的流被当成完整 | 客户端中途断开时 sampler 在 `Close` 中触发，`overflow=false`，记录里的部分 body 没有截断标记 |
| TUI 丢事件 | `tuiCh` 容量 512，发送用 `select … default`，高并发时事件被**静默丢弃**，条目可能永远停在 pending |

建议把"请求侧 / 响应侧 / 失败"三个事件改为按 reqID 汇合（两侧都到或显式失败才落盘），
取代现在"请求先到、响应查表"的隐含时序假设。

---

## HTTP/2 与 gRPC —— 建议再推迟一版，放到 v1.4

v1.2 评估把它排进 v1.3。本轮的判断是：**上面 5 项都比 h2 优先**。

- P0 两项分别是现有用户的**功能回归**和**安全暴露**，不能等一个大特性。
- P1 的三项都是"抓不到 / 对不上 / 连不通"，属于核心承诺（"see every request and response"）
  在主流工具上不成立，修复成本都是小时级。
- h2 需要重做 MITM 侧（ALPN、`http2.Server` 接管 tunnel）、输出模型（多路复用下的编号与交错，
  恰好依赖上面 P1 的"输出按 ID 成块"先落地）以及 TUI。先把输出模型理顺再上 h2，返工更少。

---

## 建议的发布节奏

**v1.2.2（立即）**

| # | 内容 | 类型 |
|---|------|------|
| P0 | `sampleBody` 不包装 `NoBody`，恢复 CL=0 请求的原始帧格式 + 回归测试 | fix |

**v1.3.0**

| # | 内容 | 类型 |
|---|------|------|
| P0 | 默认绑定 `127.0.0.1`，新增 `--listen`，默认端口改为随机 | ⚠ security / breaking |
| P1 | 文本输出按请求编号成块、加锁写出 | fix |
| P1 | 注入 `GIT_SSL_CAINFO`、`CURL_CA_BUNDLE`、`NODE_USE_ENV_PROXY=1` 等 | feat |
| P1 | replay / WSS 共用上游 Transport，遵守 `--upstream-proxy` 与环境代理 | fix |
| P2 | 记录按 reqID 汇合，修早响应丢失和 pending 泄漏；中断流标记截断 | fix |
| — | 测试：CL=0 帧格式、非回环地址不可连、并发文本输出可归属、三条出站路径都走代理 | test |
| — | README：`--listen`、支持的工具列表、Java 等未覆盖场景写进 Limitations | docs |

**v1.4.0**：HTTP/2 端到端 + gRPC 观测。

一句话总结：v1.2 解决了"能实时看到"，但顺手引入了一个会让 S3 上传失败的回归；
v1.3 的主题应该是**可信** —— 不改写用户的请求、不把本机暴露给网络、
抓到的每一条都能对上号、该抓的工具一个不漏。
