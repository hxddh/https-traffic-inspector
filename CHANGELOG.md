# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
