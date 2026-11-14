# httpmon

A zero-config HTTPS traffic inspector for the terminal.  
Wrap any CLI command — curl, aws, python, node, java — and see every request and response in real time, no browser or GUI required.

```
httpmon curl https://api.github.com/users/octocat
```

```
=== REQUEST #1 ===
Time: 14:32:01
GET https://api.github.com/users/octocat HTTP/2.0
Host: api.github.com

Headers:
  Accept: */*
  User-Agent: curl/8.4.0

=== RESPONSE #1 ===
HTTP/2.0 200 OK (212ms)

Headers:
  Content-Type: application/json; charset=utf-8
  X-Ratelimit-Remaining: 59

--- RESPONSE #1 body ---
{"login":"octocat","id":583231,...}

---------------------------------------------------- #1 end
```

httpmon writes this to **stderr**. The command's own stdout is left exactly as
the command wrote it, so `httpmon curl -s … | jq .` still pipes curl's output
to jq.

> **Upgrading from 1.x?** See [Migrating from 1.x](#migrating-from-1x): output
> moved to stderr, recordings use a new format, and credentials are masked in
> output by default.

---

## How it works

httpmon starts a local MITM proxy, generates a CA on the fly, and injects the proxy address and CA certificate into the wrapped command's environment.  
No system configuration is changed, and the temporary CA bundle is removed when the command exits.

- **HTTP** — forwarded and logged transparently
- **HTTPS** — intercepted via TLS termination with a per-host certificate signed by the CA
- **HTTP/2 and gRPC** — negotiated with the client via ALPN and with the upstream independently; trailers are carried through, and gRPC calls show their status
- **WebSocket (`wss://` and `ws://`)** — the handshake is proxied, and every message is decoded and shown as it passes, `permessage-deflate` included
- **Body display** — compressed responses (gzip, deflate, brotli, zstd) are decompressed automatically; only the first 1 KB is shown by default, the full stream is forwarded unmodified
- **Faithful forwarding** — the upstream sees the request the client sent: its own `Host`, its own `Accept-Encoding`, its own body framing
- **Safe display** — escape sequences in bodies and headers are shown, not executed, and credentials are masked
- **HAR export** — all captured traffic can be written to an HTTP Archive (`.har`) file

---

## Installation

### go install (requires Go 1.26+)

```bash
go install github.com/hxddh/https-traffic-inspector/v2@latest
```

The binary is installed as `https-traffic-inspector`; rename or alias it to `httpmon`.

### Pre-built binaries

Download the latest binary for your platform from the [Releases](https://github.com/hxddh/https-traffic-inspector/releases) page:

| Platform | File |
|----------|------|
| macOS Apple Silicon (M1/M2/M3) | `httpmon-<version>-macos-arm64` |
| macOS Intel | `httpmon-<version>-macos-amd64` |
| Linux x86-64 | `httpmon-<version>-linux-amd64` |
| Linux arm64 (Graviton, Pi) | `httpmon-<version>-linux-arm64` |
| Windows x86-64 | `httpmon-<version>-windows-amd64.exe` |

```bash
# macOS / Linux — replace <version> with the release tag, e.g. v2.0.0
chmod +x httpmon-v2.0.0-macos-arm64
sudo mv httpmon-v2.0.0-macos-arm64 /usr/local/bin/httpmon
```

### From source

```bash
git clone https://github.com/hxddh/https-traffic-inspector
cd https-traffic-inspector
go build -o httpmon .
sudo mv httpmon /usr/local/bin/
```

---

## Usage

```
httpmon [options] <command> [args...]
httpmon --replay <file> [--replay-target <url>]
httpmon --ca-dir <dir>
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | _(stderr)_ | Write httpmon's output to a file. `-` writes it to stdout, where 1.x wrote it. |
| `--format` | `text` | Output format: `text` or `json` (NDJSON). |
| `--filter` | _(none)_ | Case-insensitive substring; only matching requests are logged. Non-matching traffic is still proxied. |
| `--ui` | `false` | Launch the interactive terminal UI. |
| `--record` | _(none)_ | Append recorded traffic to an NDJSON file. |
| `--har` | _(none)_ | Write captured traffic as HAR 1.2 JSON. |
| `--show-secrets` | `false` | Show credentials in output instead of masking them. |
| `--redact` | `false` | Mask credentials in `--record` and `--har` files too. |
| `--ca-dir` | `$HTTPMON_CA_DIR` | Keep the CA in this directory across runs, creating it on first use. |
| `--port` | `0` | Proxy listen port. `0` picks a random free port. |
| `--listen` | `127.0.0.1` | Address the proxy listens on. Only loopback is safe: any other address lets anyone who can reach it use the proxy, including to reach services bound to this machine's loopback. |
| `--cert-ttl` | `1h` | How long per-host TLS certificates are cached. `0` disables caching. |
| `--replay` | _(none)_ | Replay a recorded file (no proxy or command needed). |
| `--replay-target` | _(none)_ | Override the base URL when replaying (e.g. `https://staging.example.com`). |
| `--replay-delay` | `0` | Pause between replayed requests. |
| `--replay-fail-on-diff` | `false` | Exit with code `2` if any replayed response differs from the recording. |
| `--insecure-upstream` | `false` | Skip TLS certificate verification for upstream servers. |
| `--upstream-proxy` | _(env)_ | Proxy for httpmon's own upstream requests. Defaults to `HTTP_PROXY`/`HTTPS_PROXY` from the environment. |
| `--max-body` | `1000` | Max bytes of each body shown in output. |
| `--max-capture` | `1048576` | Max bytes of each body kept for `--record` / `--har` and decompression. |
| `--no-color` | `false` | Disable colour. Colour is only used when output is a terminal, and `NO_COLOR` is honoured. |
| `--version` | | Print version and exit. |

### Exit codes

| Code | Meaning |
|------|---------|
| _(subprocess code)_ | The wrapped command's own exit code is passed through. |
| `1` | httpmon failed to start, or writing the HAR file failed. In replay mode: the recording could not be read or parsed. |
| `2` | Replay mode only, with `--replay-fail-on-diff`: at least one response differed from the recording. |

---

## Features

### Output — stderr, or `-o <file>`

httpmon's output — text blocks or NDJSON — goes to stderr, and its startup
banner and diagnostics go there too. The wrapped command's stdout is never
touched:

```bash
httpmon curl -s https://api.github.com/users/octocat | jq .login   # jq gets curl's output
httpmon curl -o page.html https://example.com                      # page.html holds the page only
httpmon --format json -o trace.ndjson python3 app.py               # NDJSON to a file
httpmon -o - curl https://example.com                              # the 1.x behaviour
```

Replay mode has no wrapped command, so its results go to stdout unless `-o` says otherwise.

---

### Automatic injection

httpmon handles proxy configuration automatically for common tools:

| Tool | What is injected |
|------|------------------|
| **curl** | `-x http://127.0.0.1:<port> --cacert <ca>`; a `--cacert` of your own is merged with httpmon's CA (plus `CURL_CA_BUNDLE` for curl run from scripts) |
| **aws** / boto3 | `AWS_CA_BUNDLE` |
| **Python requests** / **pip** | `REQUESTS_CA_BUNDLE`, `PIP_CERT` |
| **Node.js** | `NODE_EXTRA_CA_CERTS`, and `NODE_USE_ENV_PROXY=1` so the built-in `fetch` uses the proxy |
| **Java** (java, Gradle, Maven, sbt, Kotlin) | `JAVA_TOOL_OPTIONS` with the proxy properties and a PKCS#12 truststore holding the system CAs and httpmon's |
| **git** | `GIT_SSL_CAINFO` |
| **cargo** / **Deno** | `CARGO_HTTP_CAINFO` / `DENO_CERT` |
| **gRPC C-core** (Python `grpcio`, Ruby, PHP) | `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` |
| Any HTTP-proxy-aware tool | `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE` |

These override any inherited value of the same name, which would otherwise
point the tool at a bundle that lacks httpmon's CA. Inherited
`JAVA_TOOL_OPTIONS` are kept and httpmon's are appended after them, so they
take precedence. A JVM prints `Picked up JAVA_TOOL_OPTIONS: …` to stderr when
it starts; that is expected. `NODE_USE_ENV_PROXY` needs Node 22.21 or 24;
older Node versions ignore it, and their built-in `fetch` bypasses httpmon.

httpmon also clears `NO_PROXY` (and Java's `http.nonProxyHosts`) for the
wrapped command. A host named in an inherited no-proxy list would otherwise
skip httpmon and go uncaptured with no warning. httpmon's own upstream requests
still honour the real `NO_PROXY`, so routing is unchanged — the traffic just
passes through httpmon on the way.

The CA bundle written to disk contains both the proxy CA and the system's trusted CA store (when found), so direct TLS connections made by the subprocess also work correctly.

---

### Credential masking

Captures get pasted into issues, chats and AI assistants. httpmon therefore
masks credentials in everything it shows — text, `--format json` and the TUI:

```
Headers:
  Authorization: Bearer eyJh…(812 chars)
  Cookie: session=4f2a…(32 chars); theme=…(4 chars)
```

Masked are `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
`X-Api-Key` and similar API-key headers, and URL parameters such as
`access_token`, `api_key`, `key` and the signatures of pre-signed S3 and GCS
URLs. The auth scheme, cookie names and the first four characters of a long
value stay visible, so two tokens can still be told apart.

- `--show-secrets` shows them in full.
- `--record` and `--har` files keep credentials, since replay needs them. They
  are created readable by their owner only. `--redact` masks credentials in
  them too, for files you mean to share; replay then skips requests whose
  credentials were masked.

Bodies are not masked: a token inside a JSON body is shown as it is.

---

### Filter — `--filter`

Focus on the traffic you care about. Non-matching requests are still proxied silently.

```bash
# Only log requests to /api paths
httpmon --filter /api curl https://example.com/api/v1/users

# Only log requests to a specific domain
httpmon --filter stripe.com python3 payment_service.py

# Watch S3 uploads only
httpmon --filter s3 aws s3 sync ./dist s3://my-bucket/
```

---

### JSON output — `--format json`

Emits one NDJSON object per event, correlated by `id` / `req_id`.

```bash
httpmon --format json -o trace.ndjson curl https://api.github.com
jq 'select(.status) | .status' trace.ndjson

# Or pipe httpmon's stream and discard the command's own output
httpmon --format json curl -s https://api.github.com 2>&1 >/dev/null | jq '.url // empty'
```

| Object | Fields |
|--------|--------|
| Request | `id`, `time`, `method`, `url`, `proto`, `host`, `headers`, `body`, `body_truncated` |
| Response | `req_id`, `status`, `proto`, `headers`, `body`, `body_truncated`, `duration_ms`, `trailers` |
| Failure (no response) | `req_id`, `error`, `duration_ms` |
| WebSocket message | `req_id`, `ws` (`client` or `server`), `type`, `size`, `compressed`, `data`, `truncated`, `close_code`, `close_reason` |
| WebSocket closed | `req_id`, `ws_closed`, `messages`, `duration_ms` |

---

### Interactive TUI — `--ui`

A full-screen terminal UI powered by [Bubble Tea](https://github.com/charmbracelet/bubbletea).

```bash
httpmon --ui curl https://api.github.com
httpmon --ui aws s3 ls
```

```
 httpmon  proxy :41873                             3 requests
 #     Method   Status  URL                          Duration
 1     GET      200     api.github.com/users/octocat  245ms
 2 ▶   POST     201     api.github.com/repos          123ms
 3     GET      ERR     api.example.invalid/          2ms
──────────────────────────────────────────────────────────────
 ━━ REQUEST #2 ━━
 POST https://api.github.com/repos
 Host: api.github.com    Time: 14:32:01

 ━━ RESPONSE: 201 Created  (123ms) ━━
 {"id":12345,"name":"my-repo",...}
──────────────────────────────────────────────────────────────
 [↑↓/jk] move  [enter] detail  [/] search  [c] copy curl  [e] export  [q] quit
```

| Key | Action |
|-----|--------|
| `↑` / `k`, `↓` / `j` | Move up / down |
| `Enter` / `Space` | Toggle detail panel |
| `g` / `G` | Jump to first / last entry |
| `/` | Search: type to filter by method, URL, status or error; `Enter` applies, `Esc` clears |
| `c` | Copy the selected request as a `curl` command (via OSC 52, which works over SSH) |
| `e` | Export the selected entry's detail to `httpmon-<pid>-<id>.txt` |
| `PgUp` / `PgDn`, `Ctrl-U` / `Ctrl-D` | Scroll the detail panel |
| `Home` / `End` | Jump to top / bottom of the detail panel |
| `Esc` | Close the detail panel, or clear the search |
| `q` | Quit (also terminates the subprocess) |

Pending entries update in place when the response arrives; a request that
gets no response shows `ERR` and its error. WebSocket connections show `WS`
while open and list their messages in the detail panel. Warnings — an upstream
certificate that failed verification, a client that rejected httpmon's CA —
appear on the status bar instead of being written over the screen, and are
printed again when the UI exits.

The command runs without stdin while the UI owns the keyboard. Its stdout and
stderr are held back and written to stdout and stderr when the UI exits. When
stdout is redirected, the UI draws on stderr. The list keeps the most recent
5,000 entries.

---

### Body decompression

httpmon automatically decompresses `gzip`, `deflate`, `brotli` (`br`) and `zstd` encoded response bodies before display. Most HTTPS APIs compress their responses — GitHub and anything behind Cloudflare default to `br` — so you see the decoded JSON or HTML rather than a binary placeholder.

Chained encodings (`Content-Encoding: gzip, br`) are decoded layer by layer. An encoding httpmon does not recognise is shown as a `[<encoding>, N+ bytes]` placeholder rather than being printed raw.

The full compressed stream is still forwarded to the subprocess unmodified,
and httpmon never asks the upstream for compression the client did not ask for.

When only part of a large body was captured, the decoded prefix is shown followed by a `… [truncated]` marker, so a cut-off body is never mistaken for a complete one. Raise `--max-capture` to decode more.

---

### Streaming

Streaming responses and uploads are forwarded as they arrive rather than being
buffered. Server-Sent Events, chunked uploads, long-polling and slow downloads
all pass through with no added latency — the body is sampled for logging
alongside delivery, not ahead of it.

```bash
httpmon curl -N https://api.example.com/events    # SSE arrives event by event
```

The body of a stream is logged once the stream ends; its headers appear
immediately.

---

### HTTP/2 and gRPC

httpmon offers HTTP/2 to the wrapped command through ALPN and negotiates it
with the upstream separately, so each side gets the best protocol it
supports — an HTTP/2 client talking to an HTTP/1.1-only server works, and so
does the reverse. Response trailers are forwarded, and `TE: trailers` is kept,
which is what gRPC needs to work end to end.

Inside a `CONNECT` tunnel httpmon also accepts cleartext HTTP/2 with prior
knowledge. That is how an insecure gRPC client (`grpc.insecure_channel`,
`grpc.WithTransportCredentials(insecure.NewCredentials())`) talks through a
proxy, and the request goes upstream the same way.

gRPC messages are length-prefixed binary, so bodies are summarised rather than
printed, and the call's status is decoded from the trailers:

```
=== RESPONSE #2 ===
HTTP/2.0 200 OK (1ms)

Headers:
  Content-Type: application/grpc

--- RESPONSE #2 body ---
[gRPC: 1 message, 0 payload bytes]

Trailers:
  Grpc-Status: 5

gRPC status: 5 NOT_FOUND
```

`--format json` reports trailers in a `trailers` field, and `--record` in
`resp_trailers`. Recordings keep the call's bytes, so `--replay` re-sends
gRPC calls and compares their `grpc-status` as well as the body.

---

### WebSocket

`wss://` connections established via CONNECT tunnels, and plaintext `ws://`
upgrades sent to the proxy, are handled transparently. After the `101`
response the two sides are spliced without buffering, and httpmon decodes
the frames it relays:

```
=== RESPONSE #1 ===
HTTP/1.1 101 Switching Protocols (3ms)

--- WS #1 client→server text (172 bytes, 21 compressed) ---
{"op":"subscribe","channel":"trades"}

--- WS #1 server→client text (48 bytes) ---
{"op":"ack","channel":"trades"}

--- WS #1 client→server close 1000 normal ---
bye

=== WS #1 closed: 3 messages in 4.2s ===
```

Fragmented messages are reassembled, `permessage-deflate` is decompressed —
with or without context takeover — and close frames show their code and
reason. Binary messages are summarised by size. `--record` and `--har` store
the messages too (up to 1,000 per connection); HAR uses the
`_webSocketMessages` field Chrome DevTools reads.

---

### Recording — `--record`

Save all intercepted traffic to an NDJSON file for later replay or analysis.

```bash
httpmon --record traffic.ndjson curl https://api.github.com/users/octocat
httpmon --ui --record session.ndjson python3 app.py
httpmon --filter /api --record api.ndjson curl https://example.com/api/v1
```

Each line is a complete exchange, stored as it crossed the wire (record format v2):

```json
{
  "v": 2,
  "session": "20261114T143201Z-4f2a9c1e",
  "seq": 1,
  "time": "2026-11-14T14:32:01.123Z",
  "kind": "http",
  "method": "POST",
  "url": "https://api.example.com/upload",
  "proto": "HTTP/2.0",
  "req_headers": [["Content-Type", "application/octet-stream"]],
  "req_body": {"encoding": "base64", "data": "iVBORw0KGgo…", "size": 300},
  "status": 200,
  "status_text": "200 OK",
  "resp_headers": [["Content-Encoding", "gzip"], ["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]],
  "resp_body": {"encoding": "base64", "data": "H4sIAAAA…", "size": 41, "decoded": "{\"ok\":true}"},
  "duration_ms": 245.31
}
```

- **Headers** are `[name, value]` pairs in a stable order; repeated headers such as `Set-Cookie` are kept separately.
- **Bodies** are the raw bytes: UTF-8 text as it is, anything else base64. A compressed body also carries `decoded`, its text with the `Content-Encoding` removed.
- `size` is the number of bytes on the wire. When only a prefix was stored — the body exceeded `--max-capture`, or the stream was cut off — `truncated` is `true`.
- `session` and `seq` identify each exchange uniquely, even in a file appended to by several runs.
- An exchange that got no response has `error` and no response fields.
- A WebSocket connection has `"kind": "websocket"` and its messages in `ws_messages`.

---

### Replay — `--replay`

Re-issue recorded requests and compare the responses. Useful for regression testing or comparing environments.

```bash
# Replay against the original service
httpmon --replay traffic.ndjson

# Replay against a different environment
httpmon --replay traffic.ndjson --replay-target https://staging.example.com

# Replay with realistic pacing
httpmon --replay traffic.ndjson --replay-delay 500ms

# Gate a CI job on the responses being unchanged (exits 2 on any difference)
httpmon --replay traffic.ndjson --replay-target https://staging.example.com --replay-fail-on-diff

# Machine-readable results, one JSON object per replayed request
httpmon --replay traffic.ndjson --format json | jq 'select(.status_match | not)'
```

Requests are re-sent byte for byte, and response bodies are compared after
removing their `Content-Encoding`, so a binary or compressed response that has
not changed compares equal.

```
── REPLAY #1 (session 20261114T143201Z-4f2a9c1e) ──
Original:  GET https://api.example.com/users  →  200 OK
Replaying: GET https://staging.example.com/users
  Status:  ✓  recorded=200  actual=200  (43ms)
  Body:    ✓ unchanged
```

An exchange that cannot be reproduced faithfully is skipped, with the reason,
rather than approximated: a WebSocket connection, an exchange that got no
response, a request body that was only partly recorded, or a request whose
credentials were masked by `--redact`.

Recordings made by httpmon 1.x are still replayed. They hold the
human-readable view of each body, so requests whose body was binary,
compressed or truncated are skipped, and responses are compared view to view.

---

### HAR export — `--har`

Write all captured traffic to an [HTTP Archive](https://en.wikipedia.org/wiki/HAR_(file_format)) file (HAR 1.2). HAR files can be imported into Chrome DevTools, Charles Proxy, Postman, and other analysis tools.

```bash
httpmon --har session.har curl https://api.github.com
httpmon --ui --har api.har --filter /api python3 app.py
httpmon --har shareable.har --redact python3 app.py   # credentials masked
```

Entries are written as each exchange completes, so memory stays flat in a long
session. Binary bodies are stored base64-encoded, `bodySize` is the number of
bytes on the wire, and `timings` separates waiting for the response from
receiving its body. A request that got no response has status `0` and its
error in `_error`. The file is created readable by its owner only.

---

### Persistent CA — `--ca-dir`

By default the CA exists only in memory for one run, which is all a tool that
reads httpmon's environment needs. A phone, an emulator, a browser profile or a
container image keeps its own trust store; for those, keep the CA across runs
and trust it once:

```bash
httpmon --ca-dir ~/.httpmon            # creates the CA and prints its path
# … import ~/.httpmon/httpmon-ca.pem into the device or trust store …
httpmon --ca-dir ~/.httpmon --listen 0.0.0.0 --port 8080 sleep 3600
export HTTPMON_CA_DIR=~/.httpmon       # or set it once for every run
```

The directory holds `httpmon-ca.pem` (the certificate) and `httpmon-ca.key`
(the private key, mode 0600). **Keep it private**: anyone with the key can
intercept the traffic of every device that trusts the CA. Delete the directory
to retire the CA.

---

## Examples

```bash
# Inspect any curl request
httpmon curl https://api.github.com/repos/golang/go

# Debug AWS calls with S3 bucket/key highlighted
httpmon aws s3 cp ./file.txt s3://my-bucket/uploads/

# See what a Gradle build downloads
httpmon --filter maven ./gradlew build

# Tail only API traffic from a Python service
httpmon --filter /api python3 server.py

# Stream traffic as JSON into a log file
httpmon --format json -o traffic.ndjson node app.js

# Record prod traffic, compare against staging
httpmon --record prod.ndjson curl https://api.prod.example.com/health
httpmon --replay prod.ndjson --replay-target https://api.staging.example.com

# Save a HAR file for sharing, with credentials masked
httpmon --har trace.har --redact curl https://api.github.com

# Full session: TUI + HAR + filter
httpmon --ui --har session.har --filter /api python3 app.py

# Accept connections from a container or VM (exposes the proxy to the network)
httpmon --listen 0.0.0.0 --port 8080 python3 app.py
```

---

## Migrating from 1.x

| | 1.x | 2.0 |
|---|---|---|
| Where output goes | stdout, mixed with the command's own output | stderr; `-o <file>` for a file, `-o -` for the old behaviour |
| Startup banner | stdout | stderr |
| Credentials in output | shown | masked; `--show-secrets` shows them |
| `--record` format | v1: decoded text, `map` headers, placeholders for binary bodies | v2: raw bytes, ordered header pairs, session ids, failures, WebSocket messages |
| Replay of 1.x recordings | — | still supported; unreproducible requests are skipped |
| HAR | written at exit, mode 0644 | written as it goes, mode 0600, binary bodies base64 |
| Colour | always | only on a terminal; `--no-color` / `NO_COLOR` |
| `go install` path | `github.com/hxddh/https-traffic-inspector` | `github.com/hxddh/https-traffic-inspector/v2` |
| Go needed to build | 1.24 | 1.26 |

Scripts that parse httpmon's output from stdout need `-o -`, or better, `-o <file>`.
Scripts that read `--record` files need to read v2: `headers` are now lists of
pairs and `req_body` / `resp_body` are objects. `jq '.resp_body.decoded // .resp_body.data'`
gets a response's text.

---

## Limitations

- **Go programs skip the proxy for loopback targets.** Go's `ProxyFromEnvironment`, which grpc-go and `net/http` both use, never proxies `localhost` or `127.0.0.1`, so a Go client calling a local server is not captured. Clients in other languages are unaffected.
- **gRPC bodies are summarised, not decoded.** httpmon has no `.proto` schemas, so it shows message counts and sizes. The recording keeps the bytes.
- **Only HTTP is inspected.** A `CONNECT` tunnel carrying another protocol (SSH, SMTP, database wire protocols) is relayed untouched and noted as such. A server-first protocol waits up to one second before httpmon concludes the client is not going to speak.
- **WebSocket over HTTP/2 (RFC 8441) is not supported.** Clients fall back to an HTTP/1.1 connection for the upgrade, which works.
- **Cleartext HTTP/2 cannot be sent through `--upstream-proxy`.** An insecure gRPC call to an upstream reached only via another proxy fails.
- **A JVM that does not see `JAVA_TOOL_OPTIONS`** — started by a launcher that clears or replaces the environment, such as a Gradle daemon that was already running before httpmon started — is not configured. Stop the daemon (`./gradlew --stop`) first. A truststore path containing spaces is quoted; this was tested on JDK 21.
- **`--har` does not apply to `--replay`.** Replay mode neither starts the proxy nor captures entries.
- **A HAR file from a run that was killed** has every entry captured so far but lacks the closing `]}}`; add them to open it.
- **Bodies are logged when they finish, not when their headers arrive.** Request and response headers print as soon as they are seen, so a long-lived stream is visible while it runs, but its body is only shown once the stream ends. `--format json` and `--record` emit one complete record per exchange, so for a stream that record appears at the end.
- **Bodies are capped.** Output shows `--max-body` bytes; `--record` / `--har` / decompression keep `--max-capture` bytes. Raising `--max-capture` increases per-request memory use, since each captured body is buffered in full.
- **Masking covers headers and URLs, not bodies.**

---

## Security note

httpmon is a **local development and debugging tool**. It performs TLS interception using a CA that, by default, exists only for the duration of the process; its private key is never written to disk unless you ask for a persistent CA with `--ca-dir`. Do not use it in production environments or to intercept traffic you do not own.

**Upstream certificates are verified by default.** Because httpmon terminates TLS, the wrapped subprocess only ever validates the certificate httpmon presents — it can no longer see the real one. httpmon therefore performs that verification on its behalf, and a failure surfaces as a `502` plus an explanatory line on stderr.

`--insecure-upstream` disables that check. It is needed for self-signed or internal-CA endpoints, but while it is set **nothing in the chain validates the upstream certificate**, so the connection is open to interception. Use it only against hosts you control.

**Output is safe to view.** Control characters in bodies, headers and URLs — including the escape sequences a hostile server could use to write your clipboard (OSC 52) or rewrite the screen — are shown escaped (`\x1b`), never executed.

---

## License

MIT
