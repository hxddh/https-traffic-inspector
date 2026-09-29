# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
