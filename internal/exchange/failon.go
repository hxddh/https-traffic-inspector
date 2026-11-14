package exchange

import (
	"fmt"
	"strconv"
	"strings"
)

// FailOn decides which exchanges make a run fail (--fail-on).
type FailOn struct {
	classes map[int]bool // 4 for 4xx …
	codes   map[int]bool
	errors  bool
}

// ParseFailOn parses a comma-separated list of status classes (5xx), status
// codes (404) and "error" (no response).
func ParseFailOn(spec string) (*FailOn, error) {
	f := &FailOn{classes: map[int]bool{}, codes: map[int]bool{}}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch {
		case tok == "":
		case tok == "error":
			f.errors = true
		case len(tok) == 3 && strings.HasSuffix(tok, "xx") && tok[0] >= '1' && tok[0] <= '5':
			f.classes[int(tok[0]-'0')] = true
		default:
			code, err := strconv.Atoi(tok)
			if err != nil || code < 100 || code > 599 {
				return nil, fmt.Errorf("invalid --fail-on item %q (want a status class like 5xx, a code like 404, or error)", tok)
			}
			f.codes[code] = true
		}
	}
	return f, nil
}

// Match reports whether e should make the run fail.
func (f *FailOn) Match(e *Exchange) bool {
	if f == nil {
		return false
	}
	if e.Error != nil {
		return f.errors
	}
	return f.codes[e.Status] || f.classes[e.Status/100]
}
