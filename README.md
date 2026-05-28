# httpmon

A zero-config HTTPS traffic inspector for the terminal.  
Wrap any CLI command — curl, aws, python, node — and see every request and response in real time, no browser or GUI required.

```
httpmon curl https://api.github.com/users/octocat
```

```
=== REQUEST #1 ===
Time: 14:32:01
GET https://api.github.com/users/octocat HTTP/1.1
Host: api.github.com

Headers:
  User-Agent: curl/8.4.0
  Accept: */*

=== RESPONSE ===
HTTP/1.1 200 OK

Headers:
  Content-Type: application/json; charset=utf-8
  X-Ratelimit-Remaining: 59

Body:
{"login":"octocat","id":583231,...}
------------------------------------------------------------
```

---

## How it works

httpmon starts a local MITM proxy, generates a self-signed CA on the fly, and injects the proxy address and CA certificate into the wrapped command's environment.  
No system configuration is changed. Everything is cleaned up when the command exits.

- **HTTP** — forwarded and logged transparently
- **HTTPS** — intercepted via TLS termination with a per-host certificate signed by the ephemeral CA
- **WebSocket (`wss://`)** — upgrade handshake is proxied and frames are spliced bidirectionally
- **Body display** — compressed responses (gzip, deflate) are decompressed automatically; only the first 1 KB is shown, the full stream is forwarded unmodified
- **HAR export** — all captured traffic can be written to an HTTP Archive (`.har`) file on exit

---

## Installation

### Homebrew (macOS / Linux)

```bash
# After the first release is published:
brew tap hxddh/tap
brew install httpmon
```

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
# macOS / Linux — replace <version> with the release tag, e.g. v1.0.1
chmod +x httpmon-v1.0.1-macos-arm64
sudo mv httpmon-v1.0.1-macos-arm64 /usr/local/bin/httpmon
```

### From source (requires Go 1.24+)

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
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Proxy listen port. `0` picks a random free port. |
| `--filter` | _(none)_ | Case-insensitive substring; only matching requests are logged. Non-matching traffic is still proxied. |
| `--format` | `text` | Output format: `text` or `json` (NDJSON). |
| `--cert-ttl` | `1h` | How long per-host TLS certificates are cached. `0` disables caching. |
| `--ui` | `false` | Launch the interactive terminal UI. |
| `--record` | _(none)_ | Append recorded traffic to an NDJSON file. |
| `--har` | _(none)_ | Write captured traffic as HAR 1.2 JSON on exit. |
| `--replay` | _(none)_ | Replay a recorded file (no proxy or command needed). |
| `--replay-target` | _(none)_ | Override the base URL when replaying (e.g. `https://staging.example.com`). |
| `--replay-delay` | `0` | Pause between replayed requests. |

---

## Features

### Automatic injection

httpmon handles proxy configuration automatically for common tools:

| Tool | What is injected |
|------|-----------------|
| **curl** | `-x http://localhost:<port> --cacert <ca>` |
| **aws** | `AWS_CA_BUNDLE` |
| **Python requests** | `REQUESTS_CA_BUNDLE` |
| **Node.js** | `NODE_EXTRA_CA_CERTS` |
| Any HTTP-proxy-aware tool | `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE` |

The CA bundle written to disk contains both the proxy CA and the system's trusted CA store (when found), so direct TLS connections made by the subprocess also work correctly.

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

Emits one NDJSON object per request and one per response, correlated by `id` / `req_id`.

```bash
httpmon --format json curl https://api.github.com | jq '.url'
httpmon --format json --filter /users python3 app.py | jq 'select(.status) | .status'
```

**Request fields:** `id`, `time`, `method`, `url`, `proto`, `host`, `headers`, `body`  
**Response fields:** `req_id`, `status`, `proto`, `headers`, `body`

---

### Interactive TUI — `--ui`

A full-screen terminal UI powered by [Bubble Tea](https://github.com/charmbracelet/bubbletea).

```bash
httpmon --ui curl https://api.github.com
httpmon --ui aws s3 ls
```

```
 httpmon  proxy :8080                              3 requests
 #     Method   Status  URL                          Duration
 1     GET      200     api.github.com/users/octocat  245ms
 2 ▶   POST     201     api.github.com/repos          123ms
 3     GET      …       api.github.com/rate_limit      pending
──────────────────────────────────────────────────────────────
 ━━ REQUEST #2 ━━
 POST https://api.github.com/repos
 Host: api.github.com    Time: 14:32:01

 ━━ RESPONSE: 201 Created  (123ms) ━━
 {"id":12345,"name":"my-repo",...}
──────────────────────────────────────────────────────────────
 [↑↓/jk] navigate  [enter] detail  [g/G] top/bottom  [q] quit
```

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Enter` / `Space` | Toggle detail panel |
| `g` / `G` | Jump to first / last entry |
| `Esc` | Close detail panel |
| `q` | Quit (also terminates the subprocess) |

Pending entries (awaiting response) are highlighted and update in place when the response arrives.  
Subprocess stdout/stderr is captured during the TUI session and printed to stderr after exit.

---

### Body decompression

httpmon automatically decompresses `gzip` and `deflate` encoded response bodies before display. Most HTTPS APIs compress their responses; you see the decoded JSON or HTML rather than `[binary data, N bytes]`.

```
=== RESPONSE ===
HTTP/1.1 200 OK

Headers:
  Content-Encoding: gzip
  Content-Type: application/json

Body:
{"login":"octocat","id":583231,...}   ← decoded automatically
```

The full compressed stream is still forwarded to the subprocess unmodified.

---

### WebSocket support

`wss://` connections established via CONNECT tunnels are handled transparently. The upgrade handshake is proxied and logged; after the 101 response, frames are spliced bidirectionally between client and upstream without buffering.

```bash
httpmon node ws-client.js          # wss:// connections work automatically
httpmon --ui node ws-client.js     # upgrade handshake visible in TUI
```

---

### Recording — `--record`

Save all intercepted traffic to an NDJSON file for later replay or analysis.

```bash
# Record a curl session
httpmon --record traffic.ndjson curl https://api.github.com/users/octocat

# Record while watching the TUI
httpmon --ui --record session.ndjson python3 app.py

# Record only filtered traffic
httpmon --filter /api --record api.ndjson curl https://example.com/api/v1
```

Each line of the output file is a complete request/response pair:

```json
{
  "id": 1,
  "time": "2026-05-27T14:32:01Z",
  "method": "GET",
  "url": "https://api.github.com/users/octocat",
  "req_headers": {"Accept": "*/*", "User-Agent": "curl/8.4.0"},
  "req_body": "",
  "status": 200,
  "status_text": "200 OK",
  "resp_headers": {"Content-Type": "application/json"},
  "resp_body": "{\"login\":\"octocat\",...}",
  "duration_ms": 245
}
```

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
```

Output for each request:

```
── REPLAY #1 ──
Original:  GET https://api.example.com/users  →  200 OK
Replaying: GET https://staging.example.com/users
  Status:  ✓  recorded=200  actual=200  (43ms)
  Body:    ✓ unchanged

── REPLAY #2 ──
Original:  POST https://api.example.com/repos  →  201 Created
Replaying: POST https://staging.example.com/repos
  Status:  ✓  recorded=201  actual=201  (67ms)
  Body:    ≠ changed
    now: {"id":99,"name":"my-repo","created_at":"2026-05-27"}
```

---

### HAR export — `--har`

Write all captured traffic to an [HTTP Archive](https://en.wikipedia.org/wiki/HAR_(file_format)) file (HAR 1.2) on exit. HAR files can be imported into Chrome DevTools, Charles Proxy, Postman, and other analysis tools.

```bash
# Capture to HAR
httpmon --har session.har curl https://api.github.com

# Combine with filter and TUI
httpmon --ui --har api.har --filter /api python3 app.py
```

Open `session.har` in Chrome DevTools → Network tab → Import, or drag it into the [HAR Analyzer](https://toolbox.googleapps.com/apps/har_analyzer/).

---

## Examples

```bash
# Inspect any curl request
httpmon curl https://api.github.com/repos/golang/go

# Debug AWS calls with S3 bucket/key highlighted
httpmon aws s3 cp ./file.txt s3://my-bucket/uploads/

# Tail only API traffic from a Python service
httpmon --filter /api python3 server.py

# Stream traffic as JSON into a log file
httpmon --format json node app.js >> traffic.log

# Record prod traffic, compare against staging
httpmon --record prod.ndjson curl https://api.prod.example.com/health
httpmon --replay prod.ndjson --replay-target https://api.staging.example.com

# Save a HAR file for sharing or import into DevTools
httpmon --har trace.har curl https://api.github.com

# Full session: TUI + HAR + filter
httpmon --ui --har session.har --filter /api python3 app.py

# Use a random port to avoid conflicts (useful in CI)
httpmon --port 0 curl https://api.example.com
```

---

## Security note

httpmon is a **local development and debugging tool**. It performs TLS interception using an ephemeral self-signed CA that exists only for the duration of the process. The CA private key is never written to disk. Do not use it in production environments or to intercept traffic you do not own.

---

## License

MIT
