# httpmon v3.0.0 review 与下一个版本评估

基线：`v3.0.0`（main = `bb2dd8e`，已发布）。166 个测试函数、`-race` 干净、golangci-lint 0 issues、语句覆盖率 70.2%。

这一轮是 v3.0 发布后的第一次 review，测试对象是**发布出去的二进制**（从 Release 页面下载的 `httpmon-v3.0.0-linux-amd64`），
以及用户真正会用的安装方式。每条结论都标注了**实测**或**代码走查**。

> **实施状态（v3.1.0）**：按维护者决定，v3.0.1 不单独发布，第一部分的修复和第二部分的 `httpmon diff` 一起作为 v3.1.0 发布。
> 修复后复测：同一场景下 summary 模式峰值 RSS 从 115 MB 降到 20 MB；预签名 URL 的摘要行从 1148 字符缩到 94 字符；
> 未完成的请求逐条列出，`--fail-on incomplete` 退出码为 3。与计划不同的地方：`diff` 除了第一个不同的 JSON 路径，
> 还给出其余不同路径的数量和前几个，便于判断该不该用 `--ignore`；状态已变化时不再重复报告响应体差异。

结论先行：v3.0.0 有一个**装不上**的问题（`go install`），和一个只在新的默认模式下出现的**内存回归**，
建议立即发 **v3.0.1**。功能上的下一步是 **v3.1.0 的 `httpmon diff`**。

---

## 第一部分：v3.0.0 review

### P0 `go install` 装不上 v3（实测）

v3.0.0 的 `go.mod` 仍然是 `module github.com/hxddh/https-traffic-inspector/v2`，而 Go 要求模块路径的主版本后缀和 tag 一致：

| 命令 | 结果 |
|---|---|
| `go install …/v2@latest`（README 写的就是这条） | 装上的是 **v2.0.0**，不是 v3 |
| `go install …/v2@v3.0.0` | `invalid version: module path includes a major version suffix, so major version must match` |
| `go install …/v3@latest` | `module …@latest found (v1.4.1), but does not contain package …/v3` |

也就是说，**通过 `go install` 安装的用户拿不到 v3**，而且命令不会报错，装上的是一个行为完全不同的旧版本
（输出写到 stdout 还是 stderr、record 格式都不一样）。README 还写了一句错误的解释（"`/v2` 是模块名，不是版本"）。
v3.0 发布时我在说明里提到过这个疑点但没有验证，这次验证了：确实是问题。

**修复**：模块路径改为 `…/v3`，所有 import 跟着改；README 的安装命令改为 `go install github.com/hxddh/https-traffic-inspector/v3@latest`。
发布 v3.0.1 后用这条命令实际安装一次，确认版本正确。

附带问题（实测）：用 `go install` 构建的二进制没有经过 release workflow 的 `-ldflags -X main.version=…`，
`--version` 显示 `dev`。修复：`version` 为 `dev` 时从 `debug.ReadBuildInfo()` 读取模块版本。

### P1 默认 summary 模式下内存是 v2 的近 7 倍（实测）

v3 把"非终端时默认输出摘要"作为 agent 友好的核心设计，但摘要和 JSON 模式为了从 body 里提取错误码、按结构截断 JSON，
对**每一个** body 都缓冲到 `--max-capture`（1 MB）。实测：通过 httpmon 并发下载 100 个 5 MB 的二进制文件，峰值 RSS 分别是：

| 版本 / 模式 | 峰值 RSS |
|---|---|
| v2.0.0（默认 text） | 17 MB |
| **v3.0.0 默认（summary）** | **115 MB** |
| v3.0.0 `--format text` | 18 MB |

`npm install`、`pip install`、`aws s3 sync` 这类并发下载正是 agent 最常包装的命令，而它们恰好落在新的默认模式上。
这些 body 里绝大部分（tarball、wheel、二进制文件）摘要根本用不到。

**修复**：在响应头到达时按需决定要保留多少字节，而不是一律 1 MB：

| 模式 | 需要什么 | 保留 |
|---|---|---|
| summary | 只有 4xx/5xx 的 JSON 错误体需要提取错误码 | 状态码 ≥ 400 且是 JSON 类型时保留到 `--max-capture`，否则不保留，只计字节数 |
| json | JSON / gRPC 需要解析；文本只显示 `--max-body`；二进制只要大小 | JSON/gRPC 保留到 `--max-capture`；文本 `--max-body`；二进制 0 |
| text / TUI | 不变 | 不变 |
| `--record` / `--har` | 原始字节 | 不变（`--max-capture`） |

请求体同理：summary 模式不需要请求体。加一个回归测试，断言 summary 模式下二进制响应保留的字节数为 0、并且仍然报告了正确的 `size`。

### P1 一条预签名 URL 让一行摘要变成 1148 个字符（实测）

摘要行打印完整 URL。S3/GCS 预签名 URL、带长查询参数的分页链接很常见。实测一条约 1.1 KB 的预签名 URL 生成了 **1148 个字符**（约 290 tokens）的摘要行，
是普通摘要行的 20 倍以上，直接抵消了摘要格式省 token 的设计目标。凭据参数已经被遮蔽，但长度没有处理。

**修复**：摘要行里 URL 的路径保留，查询串超过一定长度（例如 60 个字符）时截短，例如 `?X-Amz-Algorithm=…(+1084 chars)`；
完整 URL 仍然在 `query --id` 和 JSON 里。单测覆盖：任何摘要行不超过约 200 个字符（错误信息另算）。

### P2 汇总只说 "1 incomplete"，不说是哪个（实测）

命令退出时还没完成的请求（服务端挂起、后台进程发出的请求），汇总里只有一个计数：

```
#1 GET 127.0.0.1:18300/ok → 200 (1ms, 2 B)
── 1 exchange: 1×2xx, 1 incomplete · slowest #1 1ms
```

而"哪个请求挂住了"往往正是 agent 要找的答案（超时、死锁、慢依赖）。record 里也没有它，因为 record 只在交换完成时写入。

**修复**：跟踪进行中的请求（编号、方法、URL、开始时间）。退出时在汇总前为每个未完成的请求输出一行：
`#2 GET 127.0.0.1:18300/hang → … no response after 3.5s`；JSON 模式下输出 `{"event":"incomplete",…}`；
`--fail-on` 增加 `incomplete` 这一项。

### 已确认正常的项（实测）

- 发布的二进制：`--fail-on 5xx` 遇到 500 时退出码为 3，摘要行能提取出 `db_timeout`；
- `query --follow` 能跟上正在写入的 record（3 个请求逐条出现）；
- Codex review 在发布前报出的 3 个问题都已修复，并有回归测试覆盖。

---

## 第二部分：v3.1.0 的功能

v3.0 评估里留到 v3.x 的三项，重新评估如下。

### `httpmon diff`：对比两次运行（建议做）

agent 最常见的循环是"改代码 → 重新运行 → 看结果有没有变"。v3.0 的 `--fail-on` 回答了"有没有失败"，
但回答不了"这次改动让程序发出的请求有什么不同"：多了或少了哪些请求、哪些状态码变了、哪个响应体变了、哪个变慢了。
现在只能把两份 record 都 `query` 出来，自己逐行比，token 成本是两份摘要加上推理。

```bash
httpmon --record before.ndjson npm test
# … 修改代码 …
httpmon --record after.ndjson npm test
httpmon diff before.ndjson after.ndjson
```

```
+ #14 POST api.example.com/v1/cache/invalidate → 204          (new)
- #9  GET  api.example.com/v1/users/7 → 200                    (gone)
~ #10 GET  api.example.com/v1/orders → 500 db_timeout ⇒ 200    (status)
~ #12 GET  api.example.com/v1/search → 200, body changed: .items[3].price
── 2 changed, 1 new, 1 gone, 31 unchanged
```

- 配对方式：按 `方法 + URL 路径 + 查询参数名` 分组，组内按出现顺序配对。不比较参数值（时间戳、nonce），也不比较编号；
- body 的差异：JSON 按路径报告第一个不同的位置，其他类型报告大小或哈希是否变化；
  `--ignore` 用来排除易变字段（`--ignore .updated_at,.request_id`）；
- 退出码：有差异为 1，没有为 0，可以直接用作 agent 的判定条件；
- `--format json` 输出结构化的差异列表。

成本中等（配对 + JSON 路径比较），完全复用 `internal/exchange` 和 `internal/body`。

### MCP server（继续推迟）

理由和 v3.0 评估时相同：能运行 httpmon 的 agent 本来就有 shell，`query` 和 `diff` 覆盖了按需读取。
P2 暴露的"进行中的请求看不到"是常驻服务唯一明确的价值，但它在退出时列出未完成请求、给 `--fail-on` 增加 `incomplete` 之后，
剩下的只是"运行过程中实时查看"。等有具体需求时再做。

### 容器支持（继续推迟）

`httpmon docker run …` 需要代理监听 docker 网桥地址，这和 v1.3 开始"默认只监听 loopback"的安全前提冲突，
需要单独设计（只监听网桥接口、只接受来自该容器的连接）。在此之前，用户可以用 `httpmon ca --dir` 加 `--listen` 手动配置，README 里已有说明。

---

## 发布节奏

**v3.0.1（立即）**

| # | 内容 |
|---|------|
| P0 | 模块路径 `…/v3`；README 安装命令；`--version` 从构建信息读取版本 |
| P1 | 按需保留 body：summary / json 模式不再一律缓冲 1 MB |
| P1 | 摘要行截短过长的查询串 |
| P2 | 退出时列出未完成的请求；`--fail-on incomplete` |
| 测试 | 发布后实际执行 `go install …/v3@latest`，确认版本正确；并发大文件下载在 summary 模式下的峰值 RSS 和 text 模式同一量级；摘要行长度上限；未完成请求出现在汇总和 JSON 事件中 |

**v3.1.0**

| # | 内容 | 类型 |
|---|------|------|
| — | `httpmon diff`：配对、状态 / 响应体 / 耗时差异、`--ignore`、退出码、JSON 输出 | feat |
| — | README、`help agents`、skill 里加入"改代码前后用 diff 对比"的用法 | docs |

**之后**：MCP server、容器支持，等有具体需求再做。

一句话总结：v3.0 的设计方向经过实测是对的（摘要约为文本的 1/20、`--fail-on` 可判定、`query` 按需展开），
但发布出去的东西有两处没对上：**`go install` 装上的是旧版本**，**新的默认模式在并发下载时多用了 6 倍内存**。
v3.0.1 修掉这两处和两个摘要细节，v3.1 用 `diff` 补上 agent 循环里"这次改了什么"这一环。
