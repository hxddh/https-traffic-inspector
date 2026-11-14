package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

// ---- terminal safety ----

// sanitizeTerminal makes untrusted text safe to write to a terminal.
//
// Bodies, header values and URLs come from servers httpmon does not control.
// Written raw, an escape sequence in them is executed by the terminal: OSC 52
// writes the user's clipboard, CSI 2J clears the screen, OSC 0 retitles the
// window. Every control character except newline and tab is therefore shown
// as a visible escape (\x1b), as are C1 controls, invalid UTF-8 (which an
// 8-bit terminal may read as C1) and the bidirectional overrides used to
// disguise text. A CR that ends a CRLF pair is dropped; a lone CR, which would
// overwrite the line, is shown.
func sanitizeTerminal(s string) string {
	return sanitize(s, false)
}

// sanitizeLine is sanitizeTerminal for text that must stay on one line, such
// as a header value: newline and tab are escaped too.
func sanitizeLine(s string) string {
	return sanitize(s, true)
}

func sanitize(s string, oneLine bool) string {
	if isTerminalSafe(s, oneLine) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n' || r == '\t':
			if oneLine {
				if r == '\n' {
					b.WriteString(`\n`)
				} else {
					b.WriteString(`\t`)
				}
			} else {
				b.WriteRune(r)
			}
		case r == '\r':
			if !oneLine && i+1 < len(s) && s[i+1] == '\n' {
				// CRLF: keep only the newline.
			} else {
				b.WriteString(`\r`)
			}
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r >= 0x80 && r < 0xa0, isBidiControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// isTerminalSafe is the fast path: most text needs no escaping at all.
func isTerminalSafe(s string, oneLine bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			// Multi-byte: decide rune by rune.
			for _, r := range s[i:] {
				if r == utf8.RuneError || (r >= 0x80 && r < 0xa0) || isBidiControl(r) ||
					(r < 0x20 && (oneLine || (r != '\n' && r != '\t'))) || r == 0x7f {
					return false
				}
			}
			return utf8.ValidString(s[i:])
		}
		if c == 0x7f || (c < 0x20 && (oneLine || (c != '\n' && c != '\t'))) {
			return false
		}
	}
	return true
}

// isBidiControl reports the embedding, override and isolate controls, which
// reorder how surrounding text is displayed.
func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f
}

// ---- credential masking ----

// showSecrets turns off masking in terminal and JSON output (--show-secrets).
// redactCaptures turns it on for --record and --har as well (--redact).
var (
	showSecrets    bool
	redactCaptures bool
)

// sensitiveHeaders carry credentials. Their values are masked in output so
// that a capture pasted into an issue or a chat does not leak them.
var sensitiveHeaders = map[string]bool{
	"authorization":        true,
	"proxy-authorization":  true,
	"cookie":               true,
	"set-cookie":           true,
	"x-api-key":            true,
	"api-key":              true,
	"apikey":               true,
	"x-auth-token":         true,
	"x-access-token":       true,
	"x-amz-security-token": true,
	"x-goog-api-key":       true,
	"x-vault-token":        true,
	"private-token":        true,
}

// sensitiveQueryParams carry credentials in URLs: OAuth tokens, API keys and
// the signatures of pre-signed S3 and GCS URLs.
var sensitiveQueryParams = map[string]bool{
	"access_token":         true,
	"id_token":             true,
	"refresh_token":        true,
	"token":                true,
	"api_key":              true,
	"apikey":               true,
	"key":                  true,
	"client_secret":        true,
	"password":             true,
	"secret":               true,
	"sig":                  true,
	"signature":            true,
	"x-amz-signature":      true,
	"x-amz-credential":     true,
	"x-amz-security-token": true,
	"x-goog-signature":     true,
	"x-goog-credential":    true,
}

func isSensitiveHeader(name string) bool { return sensitiveHeaders[strings.ToLower(name)] }

// maskToken hides a secret while keeping enough to tell two apart: the first
// four characters of a long value, and its length.
func maskToken(s string) string {
	if s == "" {
		return ""
	}
	n := utf8.RuneCountInString(s)
	keep := ""
	if n >= 16 {
		r := []rune(s)
		keep = string(r[:4])
	}
	return fmt.Sprintf("%s…(%d chars)", keep, n)
}

// maskHeaderValue masks one value of a sensitive header. An auth scheme
// (Bearer, Basic, AWS4-HMAC-SHA256…) stays visible, and cookies keep their
// names and attributes so it is still clear which ones were sent.
func maskHeaderValue(name, v string) string {
	switch strings.ToLower(name) {
	case "cookie":
		parts := strings.Split(v, ";")
		for i, p := range parts {
			parts[i] = maskPair(p)
		}
		return strings.Join(parts, ";")
	case "set-cookie":
		pair, attrs, found := strings.Cut(v, ";")
		if found {
			return maskPair(pair) + ";" + attrs
		}
		return maskPair(pair)
	}
	if i := strings.IndexByte(v, ' '); i > 0 && i <= 24 && !strings.ContainsAny(v[:i], "=;,") {
		return v[:i+1] + maskToken(v[i+1:])
	}
	return maskToken(v)
}

// maskPair masks the value of a name=value pair, keeping leading space.
func maskPair(p string) string {
	name, val, ok := strings.Cut(p, "=")
	if !ok {
		return maskToken(p)
	}
	return name + "=" + maskToken(val)
}

// maskHeaders returns h with sensitive values masked. h is not modified.
func maskHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if !isSensitiveHeader(k) {
			out[k] = vs
			continue
		}
		m := make([]string, len(vs))
		for i, v := range vs {
			m[i] = maskHeaderValue(k, v)
		}
		out[k] = m
	}
	return out
}

// maskURL masks credential-bearing query parameters and any password in the
// userinfo. The rest of the URL, including parameter order, is unchanged.
func maskURL(raw string) string {
	out := raw
	if i := strings.Index(out, "://"); i >= 0 {
		rest := out[i+3:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			if user, _, hasPass := strings.Cut(rest[:at], ":"); hasPass {
				out = out[:i+3] + user + ":…" + rest[at:]
			}
		}
	}
	q := strings.IndexByte(out, '?')
	if q < 0 {
		return out
	}
	query := out[q+1:]
	frag := ""
	if h := strings.IndexByte(query, '#'); h >= 0 {
		query, frag = query[:h], query[h:]
	}
	params := strings.Split(query, "&")
	changed := false
	for i, p := range params {
		name, val, ok := strings.Cut(p, "=")
		if ok && val != "" && sensitiveQueryParams[strings.ToLower(name)] {
			params[i] = name + "=" + maskToken(val)
			changed = true
		}
	}
	if !changed {
		return out
	}
	return out[:q+1] + strings.Join(params, "&") + frag
}

// displayHeaders and displayURL apply masking for terminal and JSON output.
func displayHeaders(h http.Header) http.Header {
	if showSecrets {
		return h
	}
	return maskHeaders(h)
}

func displayURL(u string) string {
	if showSecrets {
		return u
	}
	return maskURL(u)
}

// captureHeaders and captureURL apply masking for --record and --har, which
// keep credentials unless --redact is set: replay needs them.
func captureHeaders(h http.Header) http.Header {
	if redactCaptures {
		return maskHeaders(h)
	}
	return h
}

func captureURL(u string) string {
	if redactCaptures {
		return maskURL(u)
	}
	return u
}

// sortedKeys returns the header names in h in a stable order, so output does
// not reshuffle between runs or, in the TUI, between redraws.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
