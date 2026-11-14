package exchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/hxddh/https-traffic-inspector/v3/internal/body"
)

// ---- diff ----
//
// Diff compares two runs of the same program -- before and after a change --
// exchange by exchange. Exchanges are paired by method, path and the names of
// their query parameters (not the values, which often carry timestamps or
// nonces), in the order they occurred.

// Change kinds.
const (
	ChangeNew      = "new"      // only in the second run
	ChangeGone     = "gone"     // only in the first run
	ChangeOutcome  = "outcome"  // status, failure or gRPC status differs
	ChangeResponse = "response" // response body differs
	ChangeRequest  = "request"  // request body differs
	ChangeSlower   = "slower"   // much slower; reported, not counted as a difference
)

// Change is one difference between the runs.
type Change struct {
	Kind   string `json:"kind"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Before *Side  `json:"before,omitempty"`
	After  *Side  `json:"after,omitempty"`
	// Detail says what changed: a JSON path, sizes, durations.
	Detail string `json:"detail,omitempty"`
}

// Side is one run's view of a changed exchange.
type Side struct {
	ID         int     `json:"id"`
	Outcome    string  `json:"outcome"` // "200", "500 db_timeout", "ERR refused"
	DurationMs float64 `json:"duration_ms"`
}

// Counts summarises a diff.
type Counts struct {
	Changed   int `json:"changed"`
	New       int `json:"new"`
	Gone      int `json:"gone"`
	Unchanged int `json:"unchanged"`
	Slower    int `json:"slower,omitempty"`
}

// Differs reports whether the runs differ in anything but timing.
func (c Counts) Differs() bool { return c.Changed+c.New+c.Gone > 0 }

func (c Counts) String() string {
	s := fmt.Sprintf("── %d changed, %d new, %d gone, %d unchanged", c.Changed, c.New, c.Gone, c.Unchanged)
	if c.Slower > 0 {
		s += fmt.Sprintf(" · %d slower", c.Slower)
	}
	return s
}

// DiffOptions tunes the comparison.
type DiffOptions struct {
	// Ignore lists JSON paths whose values are not compared. A path matches
	// any path that ends in it: ".updated_at" also ignores
	// ".items[0].updated_at".
	Ignore []string
	// SlowerFactor and SlowerMinMs report a paired exchange as slower when it
	// took at least SlowerFactor times as long and SlowerMinMs more. Zero
	// turns the check off.
	SlowerFactor float64
	SlowerMinMs  float64
}

// DefaultDiffOptions report exchanges that became at least twice as slow and
// 200 ms slower: a smaller change is usually noise.
var DefaultDiffOptions = DiffOptions{SlowerFactor: 2, SlowerMinMs: 200}

// PairKey is how exchanges are matched between runs.
func PairKey(e *Exchange) string {
	u, err := url.Parse(e.URL)
	if err != nil {
		return e.Method + " " + e.URL
	}
	names := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return e.Method + " " + u.Host + u.EscapedPath() + "?" + strings.Join(names, "&")
}

// Diff compares runs a and b.
func Diff(a, b []*Exchange, opt DiffOptions) ([]Change, Counts) {
	// A record lists exchanges as they completed, which for concurrent
	// requests varies from run to run; pair them in the order they started.
	a, b = initiationOrder(a), initiationOrder(b)
	byKey := map[string][]*Exchange{}
	for _, e := range a {
		k := PairKey(e)
		byKey[k] = append(byKey[k], e)
	}
	var changes []Change
	var n Counts
	for _, after := range b {
		k := PairKey(after)
		queue := byKey[k]
		if len(queue) == 0 {
			changes = append(changes, Change{Kind: ChangeNew, Method: after.Method, URL: after.URL, After: side(after)})
			n.New++
			continue
		}
		before := queue[0]
		byKey[k] = queue[1:]
		cs := compare(before, after, opt)
		counted := false
		for _, c := range cs {
			if c.Kind == ChangeSlower {
				n.Slower++
			} else {
				counted = true
			}
		}
		if counted {
			n.Changed++
		} else {
			n.Unchanged++
		}
		changes = append(changes, cs...)
	}
	// What is left of the first run did not happen in the second, reported
	// in the order it happened.
	var gone []*Exchange
	for _, q := range byKey {
		gone = append(gone, q...)
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].ID < gone[j].ID })
	for _, e := range gone {
		changes = append(changes, Change{Kind: ChangeGone, Method: e.Method, URL: e.URL, Before: side(e)})
		n.Gone++
	}
	return changes, n
}

// initiationOrder sorts a run's exchanges by session, in the order sessions
// appear, and then by id, which is assigned when a request starts.
func initiationOrder(es []*Exchange) []*Exchange {
	session := map[string]int{}
	for _, e := range es {
		if _, ok := session[e.Session]; !ok {
			session[e.Session] = len(session)
		}
	}
	out := append([]*Exchange(nil), es...)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := session[out[i].Session], session[out[j].Session]
		if si != sj {
			return si < sj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func side(e *Exchange) *Side {
	return &Side{ID: e.ID, Outcome: Outcome(e), DurationMs: e.DurationMs}
}

// Outcome renders how an exchange ended: "200", "500 db_timeout",
// "200 grpc NOT_FOUND", "ERR refused".
func Outcome(e *Exchange) string {
	switch {
	case e.Error != nil:
		return "ERR " + e.Error.Kind
	case e.GRPC != nil && e.GRPC.Code != 0:
		return fmt.Sprintf("%d grpc %s", e.Status, e.GRPC.Name)
	case e.Hint != "":
		return fmt.Sprintf("%d %s", e.Status, e.Hint)
	}
	return fmt.Sprintf("%d", e.Status)
}

func compare(a, b *Exchange, opt DiffOptions) []Change {
	mk := func(kind, detail string) Change {
		return Change{Kind: kind, Method: b.Method, URL: b.URL, Before: side(a), After: side(b), Detail: detail}
	}
	var out []Change
	if Outcome(a) != Outcome(b) {
		out = append(out, mk(ChangeOutcome, Outcome(a)+" ⇒ "+Outcome(b)))
	}
	if d := bodyDiff(requestBody(a), requestBody(b), opt.Ignore); d != "" {
		out = append(out, mk(ChangeRequest, d))
	}
	// A changed outcome already explains a different response body.
	if a.Error == nil && b.Error == nil && Outcome(a) == Outcome(b) {
		if d := bodyDiff(responseBody(a), responseBody(b), opt.Ignore); d != "" {
			out = append(out, mk(ChangeResponse, d))
		}
	}
	if opt.SlowerFactor > 0 && a.Error == nil && b.Error == nil && a.WebSocket == nil &&
		b.DurationMs >= a.DurationMs*opt.SlowerFactor && b.DurationMs-a.DurationMs >= opt.SlowerMinMs {
		out = append(out, mk(ChangeSlower, fmt.Sprintf("%s ⇒ %s", formatMs(a.DurationMs), formatMs(b.DurationMs))))
	}
	return out
}

func requestBody(e *Exchange) *body.Rendered { return e.Request.Body }

func responseBody(e *Exchange) *body.Rendered {
	if e.Response == nil {
		return nil
	}
	return e.Response.Body
}

// content returns a body's decoded bytes and whether they are the whole
// body. A record has the raw bytes; a --format json file only the rendering.
func content(r *body.Rendered) ([]byte, bool) {
	if r == nil {
		return nil, true
	}
	if r.Raw != nil {
		raw, err := r.Raw.Bytes()
		if err == nil {
			truncated := r.Raw.Truncated
			if len(body.SplitEncodings(r.ContentEncoding)) > 0 {
				if res, err := body.Decompress(r.ContentEncoding, raw); err == nil {
					raw, truncated = res.Data, truncated || res.Truncated
				}
			}
			return raw, !truncated
		}
	}
	switch {
	case r.JSON != nil:
		b, _ := json.Marshal(r.JSON)
		return b, !r.Truncated
	case r.Text != nil:
		return []byte(*r.Text), !r.Truncated
	}
	return nil, false
}

// bodyDiff describes how two bodies differ, or returns "" when they do not.
// JSON bodies are compared by value and the first differing path is named;
// other bodies by their bytes.
func bodyDiff(a, b *body.Rendered, ignore []string) string {
	ab, aWhole := content(a)
	bb, bWhole := content(b)
	if a == nil && b == nil {
		return ""
	}
	if !aWhole || !bWhole {
		// Only prefixes were kept. Bodies of different known sizes differ
		// whatever their prefixes say; otherwise compare what both have.
		as, bs := sizeOf(a, ab), sizeOf(b, bb)
		if a != nil && b != nil && a.Size > 0 && b.Size > 0 && as != bs {
			return fmt.Sprintf("%d ⇒ %d bytes", as, bs)
		}
		n := min(len(ab), len(bb))
		if bytes.Equal(ab[:n], bb[:n]) {
			return ""
		}
	}
	av, aerr := body.ParseJSON(ab)
	bv, berr := body.ParseJSON(bb)
	if aerr == nil && berr == nil {
		var paths []string
		diffPaths(av, bv, "", ignore, &paths)
		switch {
		case len(paths) == 0:
			return ""
		case paths[0] == "":
			return "(the whole body)"
		case len(paths) == 1:
			return paths[0]
		}
		more := fmt.Sprintf("%d", len(paths)-1)
		if len(paths) >= maxDiffPaths {
			more += "+"
		}
		// Naming the others' count tells the reader whether to --ignore
		// something volatile, such as a timestamp.
		return fmt.Sprintf("%s (+%s more: %s)", paths[0], more, strings.Join(paths[1:min(len(paths), 4)], ", "))
	}
	if bytes.Equal(ab, bb) {
		return ""
	}
	return fmt.Sprintf("%d ⇒ %d bytes", sizeOf(a, ab), sizeOf(b, bb))
}

func sizeOf(r *body.Rendered, b []byte) int64 {
	if r != nil && r.Size > 0 {
		return r.Size
	}
	return int64(len(b))
}

func ignored(path string, ignore []string) bool {
	for _, ig := range ignore {
		if ig != "" && (path == ig || strings.HasSuffix(path, ig) && (strings.HasPrefix(ig, ".") || strings.HasPrefix(ig, "["))) {
			return true
		}
	}
	return false
}

// maxDiffPaths bounds how many differing paths are collected.
const maxDiffPaths = 20

// diffPaths walks two JSON values and collects the paths where they differ,
// skipping ignored ones, up to maxDiffPaths.
func diffPaths(a, b any, path string, ignore []string, out *[]string) {
	if len(*out) >= maxDiffPaths || ignored(path, ignore) {
		return
	}
	add := func(p string) {
		if len(*out) < maxDiffPaths && !ignored(p, ignore) {
			*out = append(*out, p)
		}
	}
	switch av := a.(type) {
	case body.Object:
		bv, ok := b.(body.Object)
		if !ok {
			add(path)
			return
		}
		seen := map[string]bool{}
		for _, m := range av {
			seen[m.Key] = true
			p := path + "." + m.Key
			if other, present := bv.Get(m.Key); present {
				diffPaths(m.Value, other, p, ignore, out)
			} else {
				add(p)
			}
		}
		for _, m := range bv {
			if !seen[m.Key] {
				add(path + "." + m.Key)
			}
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			add(path)
			return
		}
		for i := 0; i < len(av) && i < len(bv); i++ {
			diffPaths(av[i], bv[i], fmt.Sprintf("%s[%d]", path, i), ignore, out)
		}
		if len(av) != len(bv) {
			add(fmt.Sprintf("%s (length %d ⇒ %d)", path, len(av), len(bv)))
		}
	default:
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if !bytes.Equal(ja, jb) {
			add(path)
		}
	}
}

// Line renders a change on one line, with the same shortened URL as the
// summary.
func (c Change) Line() string {
	id := ""
	switch {
	case c.Before != nil && c.After != nil:
		id = fmt.Sprintf("#%d→#%d", c.Before.ID, c.After.ID)
	case c.After != nil:
		id = fmt.Sprintf("#%d", c.After.ID)
	case c.Before != nil:
		id = fmt.Sprintf("#%d", c.Before.ID)
	}
	mark, outcome := "~", ""
	switch c.Kind {
	case ChangeNew:
		mark, outcome = "+", c.After.Outcome
	case ChangeGone:
		mark, outcome = "-", c.Before.Outcome
	default:
		outcome = c.After.Outcome
	}
	line := fmt.Sprintf("%s %s %s %s → %s", mark, id, c.Method, ShortURL(c.URL), outcome)
	switch c.Kind {
	case ChangeNew, ChangeGone:
		return line + "   (" + c.Kind + ")"
	case ChangeOutcome:
		return fmt.Sprintf("%s %s %s %s   (%s)", mark, id, c.Method, ShortURL(c.URL), c.Detail)
	case ChangeResponse:
		return line + "   response body: " + c.Detail
	case ChangeRequest:
		return line + "   request body: " + c.Detail
	case ChangeSlower:
		return line + "   slower: " + c.Detail
	}
	return line
}
