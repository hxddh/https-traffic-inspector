package textsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzLine: output for a terminal never carries an escape, a control
// character or, for one line, a line break.
func FuzzLine(f *testing.F) {
	f.Add("ok")
	f.Add("\x1b]0;title\x07red\x1b[31m")
	f.Add("a\r\nb\u202ec\x00")
	f.Fuzz(func(t *testing.T, s string) {
		l := Line(s)
		if !utf8.ValidString(l) {
			t.Fatalf("not UTF-8: %q", l)
		}
		for _, r := range l {
			if r == 0x1b || r == '\n' || r == '\r' || (r < 0x20 && r != '\t') || r == 0x7f || isBidiControl(r) {
				t.Fatalf("Line(%q) = %q keeps %U", s, l, r)
			}
		}
		if strings.ContainsRune(Terminal(s), 0x1b) {
			t.Fatalf("Terminal(%q) keeps an escape", s)
		}
	})
}
