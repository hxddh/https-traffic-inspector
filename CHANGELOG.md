# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2026-11-14

httpmon grows from a command wrapper into a traffic workbench: captures live in
named sessions, a standing proxy captures programs httpmon does not start,
rules mock endpoints and inject faults, settings files keep defaults, and an
MCP server gives agents the sessions directly. Releases are now verifiable and
installable with one command. Not compatible with 3.x options; see
[Migrating from 3.x](README.md#migrating-from-3x).

### Added

- **Sessions.** `--session NAME` keeps every exchange, raw bytes included, in a
  private directory under httpmon's home (`$HTTPMON_HOME`, else the user
  config directory); `--session-dir` puts one anywhere and `--append` adds to
  an earlier run. `query`, `diff`, `replay`, `mock` and `--mock-from` take a
  session name, a directory or a file. `httpmon sessions` lists them.
- **`httpmon proxy`**: a standing HTTP(S) proxy (default `127.0.0.1:8080`,
  session `proxy`) for browsers, phones, containers and running services,
  using the persistent CA. **`httpmon env`** prints the exports that route a
  shell through it (`sh`, `fish`, `powershell`; `--unset`).
- **Live view.** A running session publishes its in-flight exchanges;
  `httpmon query NAME --live` lists them.
- **Rules.** `--mock '[METHOD] PATTERN => STATUS [BODY|@FILE]'`,
  `--fault '… => delay 2s | reset | reset after 1KB | timeout [N%]'` and
  `--map 'HOST[:PORT] => [SCHEME://]HOST[:PORT]'` answer, break or redirect
  matching requests. Touched exchanges are marked `[mock]`/`[fault]`/`[map]`,
  carry a `rule` field, and are listed by `query --rule`; an injected failure
  has the new error kind `injected`.
- **Recorded mocks.** `--mock-from SESSION` answers requests a session has a
  response for and forwards the rest; `httpmon mock SESSION` serves a session
  as an offline mock server.
- **Query**: `--grep REGEX` searches URLs, headers and decoded bodies;
  `--format curl` prints commands that send requests again; `--format har`
  writes HAR 1.2.
- **Settings files**: `config.toml` in httpmon's home and a project's
  `.httpmon.toml` set defaults for format, fail-on, limits, rules and diff's
  ignored paths. A project file cannot set an upstream proxy, skip
  verification, change the CA, unmask credentials, or map traffic off the
  machine.
- **`httpmon mcp`**: a Model Context Protocol server over stdio with tools
  `list_sessions`, `query_exchanges`, `get_exchange`, `get_body`, `in_flight`,
  `diff_sessions`, and — with `--allow-mutations` — `add_rule` and
  `clear_rules` for a running session.
- **Delivery**: `install.sh` and `install.ps1` (checksum-verified), a container
  image at `ghcr.io/hxddh/https-traffic-inspector` (linux/amd64, arm64),
  `SHA256SUMS`, an SPDX SBOM, and build-provenance attestations for every
  binary and the image.
- **Quality gates**: CI on Linux, macOS and Windows; fuzz targets for body
  rendering, protobuf decoding, rule parsing and terminal escaping (short runs
  on every change, ten minutes each nightly); a performance budget for added
  latency and throughput.

### Changed

- **Breaking:** `--record FILE` is replaced by `--session`/`--session-dir`, and
  `--har FILE` by `httpmon query … --format har`.
- **Breaking:** the main package moved to `cmd/httpmon` and the module to
  `…/v4`: `go install github.com/hxddh/https-traffic-inspector/v4/cmd/httpmon@latest`
  installs a binary named `httpmon`.
- **Breaking:** release files are named `httpmon-<os>-<arch>` without a
  version, so `/releases/latest/download/…` links stay valid.
- **Breaking:** `proxy`, `env`, `mock`, `sessions` and `mcp` are reserved
  first arguments; wrap a command of that name with `httpmon -- <name>`.
- `httpmon ca` no longer needs `--dir`: the persistent CA lives in httpmon's
  home unless `--dir` or `$HTTPMON_CA_DIR` says otherwise.

### Fixed

- A `text/*` body that is not UTF-8 (another charset, or damaged) was put into
  the record's `text` as invalid UTF-8; the invalid bytes are now replaced
  with U+FFFD. Found by the new fuzz tests.

## [3.1.0] - 2026-11-14

Fixes found reviewing the published 3.0.0 — it could not be installed with
`go install`, and its new default output used several times the memory of the
old one — and adds `httpmon diff`.

### Fixed

- **`go install` could not install 3.0.0.** Its module path was still
  `…/v2`, so `go install …/v2@latest` — the command the README gave —
  silently installed 2.0.0, and `…/v3@latest` found no package. The module
  path is now `github.com/hxddh/https-traffic-inspector/v3`; install with
  `go install github.com/hxddh/https-traffic-inspector/v3@latest`. A binary
  built this way now reports its version instead of `dev`.
- **The summary output kept a copy of every body.** The summary and JSON
  formats buffered up to `--max-capture` of each body although the summary
  shows none. Measured with 100 parallel 5 MB downloads: 115 MB peak in 3.0.0,
  20 MB now (text output: 20 MB). A body is now kept only as far as an output
  uses it: the summary keeps an error response's JSON, JSON output keeps JSON
  and gRPC bodies and a prefix of text, and nothing of a binary body.
- **A long query string made a long summary line** — a pre-signed URL produced
  1148 characters. Query strings past 60 characters are cut at a parameter
  boundary (`?X-Amz-Algorithm=AWS4-HMAC-SHA256&…(+994 chars)`); the full URL
  is in the record.

### Added

- **`httpmon diff <before> <after>`** compares two records: exchanges that are
  new or gone, changed outcomes (`500 db_timeout ⇒ 200`), request and response
  bodies that differ — JSON by the first differing path, with a count of the
  others — and exchanges that became much slower. `--ignore` skips volatile
  JSON fields; exit status 0 means no difference, 1 differences.
- **Unfinished exchanges are named.** An exchange still waiting when the run
  ends gets its own line (`#2 GET api/x → … no response after 3.5s`), and in
  JSON an `incomplete` event; the digest used to give only a count.
  `--fail-on incomplete` turns them into exit code 3.

## [3.0.0] - 2026-11-14

3.0 makes httpmon usable by AI coding agents as well as people: compact
output by default off a terminal, one structured exchange format, exit codes
that report failed requests, a query command for recordings, and output that
untrusted content cannot imitate. It is deliberately not compatible with 2.x;
see "Migrating from 2.x" in the README.

### ⚠ Breaking

- **Subcommands.** `httpmon replay <record>`, `httpmon query <record>`,
  `httpmon ca --dir <dir>`, `httpmon schema` and `httpmon help [agents]`
  replace `--replay`, `--replay-target` (now `replay --target`),
  `--replay-delay`, `--replay-fail-on-diff` and `--ca-dir` without a command.
  Wrapping a command named like a subcommand needs `httpmon -- <name>`.
- **The default format depends on where output goes:** full text on a
  terminal, the new one-line-per-exchange summary anywhere else. `--format
  text` restores the old behaviour; `$HTTPMON_FORMAT` sets a default.
- **`--format json` writes one object per exchange** — request, response and
  outcome together — instead of one object per request and one per response.
  JSON bodies are embedded as JSON values. The start of the run, warnings and
  the end-of-run digest are objects with an `"event"` field, so every line of
  the stream parses.
- **`--record` writes the same exchange object**, plus each body's raw bytes
  (record version 3). Recordings from 1.x and 2.x are no longer read.
- **Failures are `"error": {"kind", "message"}`**, kind one of `dns`,
  `refused`, `timeout`, `tls_verify`, `tls_handshake`, `reset`, `proxy`,
  `canceled`, `other`.
- In text output every body line is prefixed with `│ `.

### Security

- **A response body could imitate httpmon's own output.** Body text started at
  the first column like httpmon's headings, so a body could forge a block —
  measured: a body produced a fake `=== RESPONSE #9 ===` and an instruction
  addressed to an AI assistant that read as httpmon output. Body lines now
  carry a prefix that headings never have, in text output, WebSocket messages
  and `query --format text`.

### Added

- **`--format summary`**: one line per exchange with its outcome and, for an
  error response, the code or message from its JSON body
  (`#10 GET api.example.com/orders → 500 db_timeout (44ms, 105 B)`), then a
  digest. Measured on 11 exchanges: 759 bytes against 15.5 KB of text output.
- **`--fail-on 5xx,error`** (`$HTTPMON_FAIL_ON`): exit code 3 when the command
  exited 0 but an exchange matched. The command's own failure still wins.
- **`httpmon query`**: list, filter (`--status`, `--method`, `--url`,
  `--error`) and expand (`--id`, `--body request|response`) the exchanges in a
  record, with `--follow` for one still being written. Bodies are re-rendered
  from the raw bytes and credentials masked unless `--show-secrets`.
- **JSON bodies are shortened by structure**: long arrays keep their first
  items (`"…(+37 more items)"`), long strings and large objects are cut, and
  the result is always valid JSON. In 2.x a cut JSON body did not parse.
- **gRPC messages are decoded without a schema** in JSON output and records:
  fields by number, nested messages, strings and repeated fields.
- **End-of-run digest** in every format: counts by status class, failures,
  incomplete exchanges, the slowest exchange, and `--fail-on` matches.
- **`httpmon help agents`**, a one-screen guide for AI agents;
  **`httpmon schema`**, the JSON Schema of an exchange; and
  `skills/httpmon/SKILL.md` and `skills/AGENTS.md` to copy into a project.
- Replay compares `grpc-status` and re-sends gRPC calls from records.

### Changed

- The code is split into `internal/textsafe` (terminal escaping, credential
  masking), `internal/body` (decoding and rendering bodies) and
  `internal/exchange` (the exchange format, summary, digest, `--fail-on`,
  error classification), shared by the proxy, `query` and `replay`.
- Text output decompresses a body only as far as it can show, instead of up to
  10 MB.
- Failure messages name the URL the client used, not the address dialled
  (which carried `:443` inside a tunnel).

## [2.0.0] - 2026-11-14

2.0 changes where httpmon's output goes, what a recording holds and what the
terminal shows. The fixes planned for 1.4.2 are included here. See
"Migrating from 1.x" in the README.

### ⚠ Breaking

- **httpmon's output goes to stderr**, along with the startup banner. In 1.x it
  shared stdout with the wrapped command, so `httpmon --format json curl … | jq`
  fed jq curl's response as well, and `httpmon curl … > page.html` saved the
  capture into the page. The command's stdout is now untouched. New
  `-o, --output <file>` writes the output to a file; `-o -` restores the 1.x
  behaviour.
- **Credentials are masked in output** — text, `--format json` and the TUI:
  `Authorization`, `Cookie`, `Set-Cookie`, API-key headers, and token and
  signature parameters in URLs (`Bearer eyJh…(812 chars)`). `--show-secrets`
  shows them. `--record` and `--har` keep them unless `--redact` is given.
- **Record format v2.** v1 stored the human-readable view of each body — a
  placeholder for anything binary — and flattened headers into a map. v2
  stores raw bytes (base64 when not UTF-8, with the decoded text alongside for
  compressed bodies), headers as ordered `[name, value]` pairs, a session id
  and sequence number, millisecond timestamps, failed exchanges with their
  error, and WebSocket messages. Replay still reads v1 files.
- **Module path is `github.com/hxddh/https-traffic-inspector/v2`**, as Go
  requires for a v2 release; `go install …/v2@latest`. Building needs Go 1.26.
- Colour is used only when output is a terminal; `--no-color` and `NO_COLOR`
  turn it off.

### Security

- **A server could inject terminal escape sequences.** Bodies, header values
  and URLs were written to the terminal as received. Measured: a `text/plain`
  body containing `OSC 52` (write the clipboard), `CSI 2J` (clear the screen)
  and `OSC 0` (set the window title) reached the terminal byte for byte. All
  control characters except newline and tab, C1 controls, invalid UTF-8 and
  bidirectional overrides are now shown escaped (`\x1b`), in text output, the
  TUI and replay output.
- The HAR file was created with the default mode (0644 under a usual umask)
  although it holds `Authorization` headers and cookies. It is now 0600, like
  `--record`.

### Added

- **WebSocket messages.** Each message of a `ws://` or `wss://` connection is
  decoded and shown as it passes: fragmented messages reassembled,
  `permessage-deflate` decompressed with or without context takeover, close
  codes and reasons. They appear in text, JSON and the TUI, in `--record`
  (`ws_messages`) and in HAR (`_webSocketMessages`, as Chrome DevTools reads
  them). The upgrade response itself is now logged; in 1.x the handshake
  showed a request and no response.
- **Java support.** The wrapped command gets `JAVA_TOOL_OPTIONS` with the proxy
  properties and a PKCS#12 truststore holding the system CAs and httpmon's.
  Measured with JDK 21: both `HttpClient` and `HttpURLConnection` go through
  httpmon and trust it with no configuration; before, Java bypassed httpmon
  entirely.
- **Persistent CA** with `--ca-dir <dir>` (or `HTTPMON_CA_DIR`), for devices
  and trust stores that cannot read httpmon's environment. `httpmon --ca-dir
  <dir>` alone creates the CA and prints its path.
- **TUI:** `/` to search, `c` to copy a request as a curl command (OSC 52),
  `e` to export an entry; failed requests show `ERR` and their error;
  warnings appear on the status bar instead of over the screen; the list is
  capped at 5,000 entries.
- **Failed exchanges are reported everywhere.** A request that got no response
  — connection refused, DNS failure, TLS verification failure — is shown as
  `=== RESPONSE #n FAILED ===`, emitted as `{"req_id":n,"error":…}` in JSON,
  recorded with `error`, and written to HAR with status 0 and `_error`. In 1.x
  it was missing from every output, and stayed pending forever in the TUI.
- Replay re-sends gRPC calls recorded in v2 format, comparing `grpc-status`
  as well as the body.
- JSON responses carry `duration_ms` and `body_truncated`; requests carry
  `body_truncated`.
- HAR `timings` separate waiting for the response from receiving its body,
  and `bodySize` is the number of bytes on the wire.

### Changed

- HAR entries are written to the file as each exchange completes, instead of
  being held in memory until exit. A killed run keeps what it captured.
- In TUI mode the wrapped command gets no stdin — the UI and the command were
  both reading the keyboard — and its stdout and stderr are replayed to
  stdout and stderr afterwards (1.x wrote both to stderr). When stdout is
  redirected, the UI draws on stderr.
- Headers and query parameters are listed in sorted order. In the TUI they
  used to reshuffle on every redraw.
- A curl command's own `--cacert` is merged with httpmon's CA instead of being
  left to fail against httpmon's certificates, and `--proxy=…`, `-xURL` and
  combined short options such as `-sk` are recognised.
- CI and release builds use the newest Go 1.26 patch release, so released
  binaries carry the standard library's latest TLS and HTTP security fixes.

### Fixed

- **HTTPS requests reached the upstream with `Host: example.com:443`.** Inside a
  tunnel the upstream request took its Host from the CONNECT target, and the
  client's own `Host` was discarded: a request whose Host differed from the
  tunnel went to the wrong virtual host, and URLs in output, `--record` and HAR
  read `https://host:443/…`. The client's Host now goes upstream, and URLs
  drop the default port.
- **Replay sent placeholders as request bodies.** A binary request body was
  recorded as `[binary data, N+ bytes]` and replay sent that text — measured: a
  300-byte upload was replayed as 25 bytes. Every binary response was also
  reported as changed, so `--replay-fail-on-diff` always failed for such
  endpoints. v2 recordings replay byte for byte; v1 recordings skip such
  requests and compare responses view to view.
- Replay of a v1 recording also skips requests whose body was truncated or
  compressed, which it used to send cut short or decoded.
- httpmon added `Accept-Encoding: gzip` to requests that had none and
  decompressed the reply itself, so the upstream saw a request the client
  never sent. `Proxy-Connection` reached HTTP/1.1 upstreams.
- Repeated response headers such as `Set-Cookie` were merged into one value in
  recordings and could not be told apart.
- Appending several runs to one `--record` file repeated ids; records now
  carry a session id.
- A body with no `Content-Type` that is not valid UTF-8 is summarised as binary
  instead of printed.

## [1.4.1] - 2026-09-29

### Fixed

- **An exchange could vanish from the output, `--record` and `--har`.** The
  response body was wrapped in the logging sampler after a deferred
  `resp.Body.Close()` had already been bound to the original body, so the
  sampler was never closed. When the copy to the client stopped before
  end-of-stream — a client that hangs up once it has every byte — the
  exchange was never reported at all. Measured with `curl` and a single
  request: 2 in 120 runs produced a HAR with no entries; now 0 in 200. In a
  200-request HTTP/2 stress run, 1 in 5 runs lost an exchange; now 0 in 10.
  Present since 1.2.0 for plain HTTP; 1.4.0 routed every request through the
  same path.
- A body that delivered its whole declared `Content-Length` is no longer
  marked truncated just because the consumer stopped before reading EOF.
- On exit, httpmon waits (up to 3s) for exchanges still being relayed, so the
  wrapped command's last request is logged and recorded before the HAR is
  written.
- **Non-HTTP traffic through a `CONNECT` tunnel is relayed instead of
  broken.** A protocol where the server speaks first (SMTP, SSH, MySQL)
  deadlocked until the client timed out, and one where the client speaks
  first but not in TLS or HTTP (Redis, Postgres, MQTT) was answered with a
  400. Such tunnels are now spliced to their target untouched and marked
  `not HTTP, relayed without inspection`.
- `--replay` skips recorded gRPC calls instead of re-sending their body
  summary as a request body, which failed against the server and reported a
  spurious difference.

## [1.4.0] - 2026-09-29

### Added

- **HTTP/2 and gRPC.** httpmon now offers HTTP/2 to the wrapped command via
  ALPN and negotiates it with the upstream independently, instead of silently
  downgrading everything to HTTP/1.1. Response trailers are forwarded and
  `TE: trailers` is kept, so gRPC works end to end. Measured with a real
  Python `grpcio` client and server: through 1.3.0 every call failed with
  `UNAVAILABLE`, both over TLS and in the clear; through 1.4.0 both succeed,
  and httpmon shows each call.
- Cleartext HTTP/2 with prior knowledge inside `CONNECT` tunnels — how an
  insecure gRPC client talks through a proxy — relayed to the upstream the
  same way. Cleartext HTTP/1.1 inside a tunnel works too.
- gRPC-aware output: bodies are summarised by message count and size, and the
  call's status is decoded from the trailers (`gRPC status: 5 NOT_FOUND`).
- Response trailers in every output: a `Trailers:` block in text, `trailers`
  in `--format json`, `resp_trailers` in `--record`, and the TUI detail panel.
- Plaintext `ws://` WebSocket upgrades, previously unsupported.
- `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` for gRPC C-core clients (Python
  `grpcio`, Ruby, PHP), which ship their own trust roots.

### Changed

- Requests inside `CONNECT` tunnels are now served by Go's standard HTTP
  server rather than a hand-written HTTP/1.1 read loop. It brings HTTP/2 with
  it and handles `Expect: 100-continue`, keep-alive and response framing, each
  of which the old loop had to patch by hand.
- A client that disconnects now cancels its upstream request.

### Fixed

- An empty `POST`/`PUT` sent over HTTP/2 (`content-length: 0`, as
  `curl --http2 -d ""` sends it) reached the upstream as
  `Transfer-Encoding: chunked` — the 1.2.2 fix applied only to HTTP/1.1
  clients. Found while testing this release, before it shipped.

## [1.3.0] - 2026-09-29

### ⚠ Breaking

- **The proxy now listens on `127.0.0.1` only, on a random free port.** It
  previously bound every interface on port 8080, so anyone on the same
  network could use it as an open proxy — including to reach services bound
  only to this machine's loopback, whose traffic then landed in the user's
  recordings. `--listen <addr>` opts into another address (for a container or
  VM) and prints a warning when it is not loopback. `--port` still fixes the
  port.

### Security

- See the listener change above.

### Added

- The wrapped command now also gets `GIT_SSL_CAINFO`, `CURL_CA_BUNDLE`,
  `CARGO_HTTP_CAINFO`, `DENO_CERT`, `PIP_CERT` and `NODE_USE_ENV_PROXY=1`, and
  `AWS_CA_BUNDLE` for every command rather than only a top-level `aws`.
  Measured before this change: `git` over https failed certificate
  verification, and Node 22's built-in `fetch` bypassed httpmon entirely, so
  nothing was captured while the command appeared to succeed. These override
  inherited values, which would point at a bundle without httpmon's CA.
- `--record` entries carry `req_body_truncated` / `resp_body_truncated`, and
  HAR bodies a `comment`, when only a prefix of the body was stored.

### Fixed

- **Text output could not be matched to requests under concurrency.** Response
  headers and bodies carried no request number and were printed line by line,
  so with `npm`, `pip` or `aws s3 sync` neither could be attributed. Every block
  is now numbered (`=== RESPONSE #3 ===`, `--- RESPONSE #3 body ---`), the
  response line shows the round-trip time, and each block is written whole.
- **`--replay` and `wss://` tunnels ignored `--upstream-proxy` and
  `HTTP(S)_PROXY`**, so both failed behind an egress proxy. All upstream
  traffic now takes the same route; WebSocket tunnels go through the proxy
  with `CONNECT`.
- An exchange whose response finished before its request body — a server
  answering an upload early with a 413 or an auth failure — was silently left
  out of `--record` and `--har`.
- Concurrent exchanges could interleave on one line of a `--record` file.
- A body cut off before it ended (a client disconnecting mid-download) was
  shown and stored as if complete. It is now marked truncated, and replay
  compares only the recorded prefix.
- A failed upstream request could leave a pending capture entry behind forever.
- The TUI dropped events under load, leaving entries stuck as pending.

## [1.2.2] - 2026-09-29

### Fixed

- **An empty `POST` or `PUT` was forwarded upstream as
  `Transfer-Encoding: chunked`** instead of `Content-Length: 0`, a regression
  from 1.2.0. The streaming body sampler also wrapped `http.NoBody`, so the
  upstream transport no longer recognised the body as empty and fell back to
  chunked framing. Servers that reject chunked requests — S3 among them —
  failed calls that worked without httpmon, such as starting a multipart
  upload. Empty bodies are now left untouched, and requests are framed exactly
  as the client sent them.

## [1.2.1] - 2026-08-04

### Fixed

- **Hosts listed in the inherited `NO_PROXY` bypassed httpmon entirely**, so
  their traffic went uncaptured with no indication that anything was missed —
  the command simply worked and httpmon printed nothing. httpmon set its own
  address as the subprocess proxy but passed the ambient no-proxy list straight
  through, and the tools people wrap most often (`go`, `pip`, `npm`) are exactly
  the ones such lists tend to name. Measured against live hosts: 0 requests
  captured for a domain in `NO_PROXY`, 1 for one that was not.

  The subprocess no-proxy list is now cleared. httpmon's own upstream client
  still applies the real `NO_PROXY`, so where traffic ultimately goes is
  unchanged — it just passes through httpmon on the way.

## [1.2.0] - 2026-08-04

### Fixed

- **Streaming was broken in both directions.** Bodies were read with
  `io.ReadFull` before anything was forwarded, and `io.ReadFull` only returns
  once its buffer is full or the stream ends. Anything that trickled — an SSE
  feed, a chunked upload, a slow download — was withheld in full until the far
  end closed. Measured against a live SSE endpoint, time-to-first-byte went
  from 0.024s direct to 6.025s through httpmon; a chunked upload of four small
  writes reached the server as a single write.

  Bodies are now sampled alongside delivery rather than ahead of it, and
  responses are flushed as they are written instead of sitting in a 32 KB
  buffer until the end. Same measurement now reports 0.034s.

  The visible consequence is that a body is logged when it finishes rather than
  when its headers arrive. Request and response *heads* still print
  immediately, so a long-lived stream is visible as it happens; `--format json`
  and `--record` emit one complete record per exchange as before.

### Added

- `--upstream-proxy`, and httpmon's own upstream requests now honour
  `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`. The upstream transport previously
  set no proxy at all, so httpmon could not run behind an egress proxy — the
  environment where inspecting traffic matters most. httpmon injects its own
  address only into the subprocess environment, so reading the environment here
  picks up the outer proxy rather than looping back.

## [1.1.3] - 2026-08-04

### Fixed

- `--replay` always verified TLS certificates and ignored `--insecure-upstream`
  — the flag was assigned after the replay branch had already returned — so a
  recording captured from a self-signed or internal-CA host could never be
  replayed. Replay now mirrors the proxy's verification policy.

## [1.1.2] - 2026-08-04

### Fixed

- **HTTPS requests could hang the wrapped command until its own timeout.** Two
  independent faults in the `CONNECT` path, both found by running httpmon
  against a real host rather than a local test server:
  - The tunnel response was written through `http.ResponseWriter`, so net/http
    appended `Date` and `Transfer-Encoding: chunked`. RFC 9110 §9.3.6 forbids
    body framing on a 2xx `CONNECT` response. httpmon now writes
    `HTTP/1.1 200 Connection Established` directly to the hijacked connection.
  - When the upstream transport transparently gunzipped a response it dropped
    `Content-Length`, leaving the length unknown. `Response.Write` then
    delimited the body by closing the connection — but the tunnel loop keeps it
    open for the next request, so the client blocked waiting for an EOF that
    never came. Such responses are now framed as `chunked`, which delimits the
    body without giving up keep-alive. This affected any gzipped HTTPS
    response, which is most of them.

## [1.1.1] - 2026-08-03

### Fixed

- An **uncompressed** response body larger than `--max-body` was still cut
  without a `… [truncated]` marker, so a shortened body looked complete — the
  silent truncation 1.1.0 claimed to have fixed. The body was peeked at exactly
  the limit, so the display step saw a string of exactly the maximum length and
  judged it whole. httpmon now peeks one byte past the limit to tell a body that
  fills it from one that overflows it. Compressed bodies were already marked
  correctly.
- The truncation marker is no longer written into `--record` and `--har`
  captures. It is a display affordance; storing it corrupted the recorded body
  and could skew `--replay` comparisons.

## [1.1.0] - 2026-08-03

### ⚠ Breaking

- **Upstream TLS certificates are now verified by default.** Previously httpmon
  accepted any upstream certificate, which silently stripped the wrapped
  subprocess of its own certificate validation. Endpoints using self-signed or
  internal-CA certificates now fail with a `502` and an explanatory message;
  pass `--insecure-upstream` to restore the old behaviour.

### Added

- Brotli (`br`) and Zstandard (`zstd`) body decompression, plus support for
  chained encodings such as `Content-Encoding: gzip, br`.
- `--insecure-upstream` to skip upstream certificate verification.
- `--max-body` and `--max-capture` to configure how much of each body is
  displayed and captured; both were previously hard-coded.
- `--replay-fail-on-diff`, which exits with code `2` when a replayed response
  differs from the recording, so replays can gate a CI job.
- `--format json` now applies to replay mode, emitting one JSON result per
  replayed request.
- `--version`, with the release tag injected at build time.
- Detail-panel scrolling in the TUI (`PgUp`/`PgDn`, `Ctrl-U`/`Ctrl-D`,
  `Home`/`End`), plus a `▼` indicator when more content is below.
- `LICENSE` (MIT), matching the licence the README already declared.
- `CHANGELOG.md`.
- golangci-lint and coverage reporting in CI.

### Security

- Recording files created by `--record` are now `0600` instead of `0644`. They
  contain complete request headers, including `Authorization` values and
  cookies, and must not be world-readable.
- The proxy listener sets a `ReadHeaderTimeout`, so a connection can no longer
  be held open indefinitely mid-header. Request bodies and hijacked `CONNECT`
  tunnels are unaffected.

### Fixed

- Replay compared the recorded body — which is stored decoded — against the raw
  response bytes, so every compressed endpoint reported a difference on every
  replay. Replayed responses are now decoded before comparison.
- The temporary CA bundle is now removed on exit. `main` ended with `os.Exit`,
  which skipped the deferred cleanup, so every run leaked a file into the
  temporary directory.
- Responses using an unsupported `Content-Encoding` were printed as raw
  compressed bytes — brotli responses from GitHub and Cloudflare rendered as
  garbage. Unsupported encodings now show a `[<encoding>, N+ bytes]` placeholder.
- A compressed body larger than the capture limit is no longer discarded
  outright: the successfully decoded prefix is shown with a `… [truncated]`
  marker.
- The TUI detail panel could not be scrolled at all — the key handler returned
  before the viewport ever saw an event, making long bodies unreachable.
- Truncated output is now marked instead of being cut silently, and is cut on a
  rune boundary so multi-byte characters are not split.
- A failure to write the HAR file is reported on stderr and reflected in the
  exit code instead of being discarded.
- Leaf certificates no longer carry a useless `*.<host>` SAN or hard-coded
  loopback IP SANs; an IP-literal host now gets an IP SAN instead of an invalid
  DNS SAN.
- `deflate` bodies sent with a zlib wrapper (which most servers use) now decode.
- The TUI request list is truncated by display width rather than byte length, so
  multi-byte URLs no longer break column alignment.
- HAR `content.size` and `bodySize` are no longer both set to the truncated body
  length; unknown values are reported as `-1` per the HAR 1.2 spec.
- The HAR `creator.version` field now reports the real version instead of a
  hard-coded `1.0`.

## [1.0.2] - 2026-05-29

- Replaced RSA-2048 with ECDSA P-256 for certificate generation.
- Dropped the Homebrew formula in favour of `go install`.

## [1.0.1] - 2026-05-28

- Renamed release binaries to `httpmon-<version>-<os>-<arch>`.
- Fixed six issues found in code review.

## [1.0.0] - 2026-05-28

Initial release: MITM proxy, filtering, JSON output, interactive TUI, traffic
recording and replay, HAR export, gzip/deflate decompression, and WebSocket
tunnelling.
