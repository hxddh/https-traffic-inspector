package textsafe

import (
	"net/http"
	"testing"
)

func TestSanitizeTerminal(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain text\nline two\ttab", "plain text\nline two\ttab"},
		{"clip \x1b]52;c;ZXZpbA==\x07", `clip \x1b]52;c;ZXZpbA==\x07`},
		{"clear \x1b[2J", `clear \x1b[2J`},
		{"crlf\r\nok", "crlf\nok"},
		{"over\rwrite", `over\rwrite`},
		{"c1 \u009b31m", `c1 \u009b31m`},
		{"bidi \u202egnp.exe", `bidi \u202egnp.exe`},
		{"bad \xff utf8", `bad \xff utf8`},
		{"unicode ünïcødé 日本", "unicode ünïcødé 日本"},
	} {
		if got := Terminal(tc.in); got != tc.want {
			t.Errorf("Terminal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := Line("a\nb\tc"); got != `a\nb\tc` {
		t.Errorf("Line kept a line break: %q", got)
	}
}

func TestMaskHeaders(t *testing.T) {
	h := http.Header{
		"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"},
		"Cookie":        {"session=abcdef0123456789abcdef; theme=dark"},
		"Set-Cookie":    {"sid=0123456789abcdef0123; Path=/; HttpOnly"},
		"X-Api-Key":     {"short"},
		"Accept":        {"*/*"},
	}
	m := MaskHeaders(h)
	if got := m.Get("Authorization"); got != "Bearer eyJh…(44 chars)" {
		t.Errorf("Authorization = %q", got)
	}
	if got := m.Get("Cookie"); got != "session=abcd…(22 chars); theme=…(4 chars)" {
		t.Errorf("Cookie = %q", got)
	}
	if got := m.Get("Set-Cookie"); got != "sid=0123…(20 chars); Path=/; HttpOnly" {
		t.Errorf("Set-Cookie = %q", got)
	}
	if got := m.Get("X-Api-Key"); got != "…(5 chars)" {
		t.Errorf("X-Api-Key = %q", got)
	}
	if got := m.Get("Accept"); got != "*/*" {
		t.Errorf("Accept was changed: %q", got)
	}
	if h.Get("Authorization") == m.Get("Authorization") {
		t.Error("MaskHeaders modified its input")
	}
}

func TestMaskURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://h/p?a=1&access_token=abcdefghijklmnopqrstuvwxyz&b=2", "https://h/p?a=1&access_token=abcd…(26 chars)&b=2"},
		{"https://s3/k?X-Amz-Signature=0123456789abcdef0123&X-Amz-Date=1", "https://s3/k?X-Amz-Signature=0123…(20 chars)&X-Amz-Date=1"},
		{"https://user:hunter2@h/p", "https://user:…@h/p"},
		{"https://h/p?q=search#frag", "https://h/p?q=search#frag"},
	} {
		if got := MaskURL(tc.in); got != tc.want {
			t.Errorf("MaskURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
