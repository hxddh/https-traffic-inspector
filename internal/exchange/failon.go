package exchange

import (
	"fmt"
	"strconv"
	"strings"
)

// FailOn decides which exchanges make a run fail (--fail-on).
type FailOn struct {
	classes  map[int]bool // 4 for 4xx …
	codes    map[int]bool
	errors   bool
	appError bool // HTTP 2xx carrying a protocol error (GraphQL, SSE, JSON-RPC, gRPC)
	// incomplete matches exchanges still unanswered when the run ends.
	incomplete bool
}

// ParseFailOn parses a comma-separated list of status classes (5xx), status
// codes (404), "error" (no response), "app_error" (protocol error inside 2xx)
// and "incomplete" (still unanswered when the run ended).
func ParseFailOn(spec string) (*FailOn, error) {
	f := &FailOn{classes: map[int]bool{}, codes: map[int]bool{}}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch {
		case tok == "":
		case tok == "error":
			f.errors = true
		case tok == "app_error":
			f.appError = true
		case tok == "incomplete":
			f.incomplete = true
		case len(tok) == 3 && strings.HasSuffix(tok, "xx") && tok[0] >= '1' && tok[0] <= '5':
			f.classes[int(tok[0]-'0')] = true
		default:
			code, err := strconv.Atoi(tok)
			if err != nil || code < 100 || code > 599 {
				return nil, fmt.Errorf("invalid --fail-on item %q (want a status class like 5xx, a code like 404, error, app_error or incomplete)", tok)
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
	if f.appError && (e.AppError != nil || (e.GRPC != nil && e.GRPC.Code != 0)) {
		return true
	}
	return f.codes[e.Status] || f.classes[e.Status/100]
}

// MatchAppError reports whether protocol-level errors inside 2xx are checked.
func (f *FailOn) MatchAppError() bool { return f != nil && f.appError }

// MatchIncomplete reports whether unfinished exchanges make the run fail.
func (f *FailOn) MatchIncomplete() bool { return f != nil && f.incomplete }
