package rules

import (
	"net/http"
	"testing"
)

// FuzzParse: no rule text panics the parser, and a parsed rule can be matched.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`GET api.example.com/v1/* => 503 {"e":1}`, "*/x => delay 2s 50%", "*/x => reset after 1KB",
		"a.com:80 => https://b.com:8443", "=>", "* * => ", "[ => 200",
		"*/x [header X-Test] => response set X-A: 1", "*/x [header Authorization: Bearer *] => 401",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, kind := range []string{KindMock, KindFault, KindMap, KindHeader} {
			if r, err := Parse(kind, s); err == nil && r.match != nil {
				r.matches("GET", "host/path", http.Header{"X-Test": {"v"}})
			}
		}
	})
}
