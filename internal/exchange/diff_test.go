package exchange

import (
	"strings"
	"testing"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
)

func ex(id int, method, url string, status int, jsonBody string, ms float64) *Exchange {
	e := &Exchange{V: Version, ID: id, Method: method, URL: url, Status: status, DurationMs: ms,
		Response: &Message{Headers: Headers{"Content-Type": {"application/json"}}}}
	if jsonBody != "" {
		e.Response.Body = &body.Rendered{Size: int64(len(jsonBody)), Raw: body.NewRaw([]byte(jsonBody), false)}
	}
	return e
}

func TestDiff(t *testing.T) {
	before := []*Exchange{
		ex(1, "GET", "https://h/items?ts=1", 200, `{"items":[{"price":1}],"updated_at":1}`, 10),
		ex(2, "GET", "https://h/orders", 500, `{"error":{"code":"db_timeout"}}`, 10),
		ex(3, "GET", "https://h/slow", 200, `{}`, 10),
		ex(4, "GET", "https://h/old", 200, `{}`, 10),
		ex(5, "GET", "https://h/same", 200, `{"a":1}`, 10),
	}
	before[1].Hint = "db_timeout"
	after := []*Exchange{
		ex(1, "GET", "https://h/items?ts=2", 200, `{"items":[{"price":2}],"updated_at":2}`, 10),
		ex(2, "GET", "https://h/orders", 200, `{"orders":[]}`, 10),
		ex(3, "GET", "https://h/slow", 200, `{}`, 900),
		ex(4, "GET", "https://h/new", 200, `{}`, 10),
		ex(5, "GET", "https://h/same", 200, `{"a":1}`, 12),
	}

	changes, n := Diff(before, after, DefaultDiffOptions)
	if n != (Counts{Changed: 2, New: 1, Gone: 1, Unchanged: 2, Slower: 1}) {
		t.Errorf("counts = %+v", n)
	}
	kinds := map[string]Change{}
	for _, c := range changes {
		kinds[c.Kind+" "+c.URL] = c
	}
	if c := kinds["response https://h/items?ts=2"]; c.Detail != ".items[0].price (+1 more: .updated_at)" {
		t.Errorf("items detail = %q", c.Detail)
	}
	if c := kinds["outcome https://h/orders"]; c.Detail != "500 db_timeout ⇒ 200" {
		t.Errorf("orders detail = %q", c.Detail)
	}
	if _, ok := kinds["response https://h/orders"]; ok {
		t.Error("a changed outcome also reported its body")
	}
	if _, ok := kinds["slower https://h/slow"]; !ok {
		t.Error("a 90x slower exchange was not reported")
	}
	if _, ok := kinds["new https://h/new"]; !ok {
		t.Error("new exchange not reported")
	}
	if _, ok := kinds["gone https://h/old"]; !ok {
		t.Error("gone exchange not reported")
	}

	// Ignoring the volatile field leaves only the real change.
	opt := DefaultDiffOptions
	opt.Ignore = []string{".updated_at"}
	changes, _ = Diff(before[:1], after[:1], opt)
	if len(changes) != 1 || changes[0].Detail != ".items[0].price" {
		t.Errorf("with --ignore: %+v", changes)
	}

	if _, n := Diff(before, before, DefaultDiffOptions); n.Differs() {
		t.Errorf("a run differs from itself: %+v", n)
	}
}

func TestPairKey_IgnoresQueryValues(t *testing.T) {
	a := PairKey(&Exchange{Method: "GET", URL: "https://h/p?ts=1&b=2"})
	b := PairKey(&Exchange{Method: "GET", URL: "https://h/p?b=9&ts=2"})
	c := PairKey(&Exchange{Method: "GET", URL: "https://h/p?other=1"})
	if a != b || a == c {
		t.Errorf("keys: %q %q %q", a, b, c)
	}
}

func TestChangeLine(t *testing.T) {
	c := Change{Kind: ChangeOutcome, Method: "GET", URL: "https://h/orders",
		Before: &Side{ID: 2, Outcome: "500 db_timeout"}, After: &Side{ID: 3, Outcome: "200"}, Detail: "500 db_timeout ⇒ 200"}
	if got := c.Line(); got != "~ #2→#3 GET h/orders   (500 db_timeout ⇒ 200)" {
		t.Errorf("Line = %q", got)
	}
}

// Regression: a pre-signed URL made a 1148-character summary line.
func TestShortURL(t *testing.T) {
	long := "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=" + strings.Repeat("A", 60) + "&X-Amz-Signature=" + strings.Repeat("f", 900)
	got := ShortURL(long)
	if len(got) > 120 || !strings.HasPrefix(got, "bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&…(+") {
		t.Errorf("ShortURL = %q (%d chars)", got, len(got))
	}
	if got := ShortURL("https://h/p?" + strings.Repeat("x", 100)); got != "h/p?"+strings.Repeat("x", 60)+"…(+40 chars)" {
		t.Errorf("one long parameter: %q", got)
	}
	if got := ShortURL("https://h/p?token=" + strings.Repeat("y", 100)); got != "h/p?token=…(+100 chars)" {
		t.Errorf("one long value: %q", got)
	}
	if got := ShortURL("https://h/p?a=1"); got != "h/p?a=1" {
		t.Errorf("short query changed: %q", got)
	}
}

func TestPending(t *testing.T) {
	p := Pending{ID: 2, Method: "GET", URL: "http://h/hang", WaitingMs: 3500}
	if got := p.SummaryLine(); got != "#2 GET h/hang → … no response after 3.5s" {
		t.Errorf("SummaryLine = %q", got)
	}
	f, _ := ParseFailOn("5xx,incomplete")
	if !f.MatchIncomplete() {
		t.Error("incomplete not parsed")
	}
	if g, _ := ParseFailOn("5xx"); g.MatchIncomplete() {
		t.Error("incomplete matched without being asked for")
	}
}

// Regression: bodies kept only as prefixes were compared by prefix alone, so
// a download that grew from 2 MB to 5 MB with the same first megabyte read as
// unchanged.
func TestDiff_TruncatedBodiesOfDifferentSizesDiffer(t *testing.T) {
	prefix := strings.Repeat("x", 100)
	mk := func(size int64) *Exchange {
		e := ex(1, "GET", "https://h/f", 200, "", 10)
		e.Response.Body = &body.Rendered{Size: size, Raw: &body.Raw{Encoding: "utf8", Data: prefix, Truncated: true}}
		return e
	}
	changes, n := Diff([]*Exchange{mk(2 << 20)}, []*Exchange{mk(5 << 20)}, DefaultDiffOptions)
	if !n.Differs() || len(changes) != 1 || changes[0].Detail != "2097152 ⇒ 5242880 bytes" {
		t.Errorf("changes = %+v", changes)
	}
	if _, n := Diff([]*Exchange{mk(2 << 20)}, []*Exchange{mk(2 << 20)}, DefaultDiffOptions); n.Differs() {
		t.Error("equal sizes and prefixes reported as different")
	}
}

// Regression: records list exchanges as they complete, so two concurrent
// requests to one endpoint finishing in the other order were paired wrongly
// and both reported as changed.
func TestDiff_PairsInInitiationOrder(t *testing.T) {
	a1 := ex(1, "POST", "https://h/items", 201, `{"name":"a"}`, 10)
	a2 := ex(2, "POST", "https://h/items", 201, `{"name":"b"}`, 10)
	b1 := ex(1, "POST", "https://h/items", 201, `{"name":"a"}`, 10)
	b2 := ex(2, "POST", "https://h/items", 201, `{"name":"b"}`, 10)
	// The second run's file has them in completion order: #2 first.
	if _, n := Diff([]*Exchange{a1, a2}, []*Exchange{b2, b1}, DefaultDiffOptions); n.Differs() {
		t.Errorf("completion order produced a difference: %+v", n)
	}
}

// A diff of light exchanges loads the full ones only where a body's digest
// differs, and finds the same changes.
func TestDiff_SlimWithLoad(t *testing.T) {
	mk := func(id int, b string) *Exchange {
		return &Exchange{V: Version, ID: id, Method: "GET", URL: "https://h/items", Status: 200,
			Response: &Message{Headers: Headers{}, Body: &body.Rendered{Size: int64(len(b)), Raw: body.NewRaw([]byte(b), false)}}}
	}
	before := []*Exchange{mk(1, `{"price":1}`), mk(2, `{"same":true}`)}
	after := []*Exchange{mk(1, `{"price":2}`), mk(2, `{"same":true}`)}
	full := map[*Exchange]*Exchange{}
	var slimA, slimB []*Exchange
	for _, l := range []struct {
		in  []*Exchange
		out *[]*Exchange
	}{{before, &slimA}, {after, &slimB}} {
		for _, e := range l.in {
			c := *e
			c.Response = &Message{Headers: e.Response.Headers, Body: e.Response.Body}
			Slim(&c)
			full[&c] = e
			*l.out = append(*l.out, &c)
		}
	}
	loads := 0
	opt := DefaultDiffOptions
	opt.Load = func(e *Exchange) (*Exchange, error) { loads++; return full[e], nil }
	changes, counts := Diff(slimA, slimB, opt)
	if counts.Changed != 1 || counts.Unchanged != 1 || len(changes) != 1 || changes[0].Detail != ".price" {
		t.Errorf("changes = %+v, counts = %+v", changes, counts)
	}
	if loads != 2 {
		t.Errorf("loaded %d exchanges, want 2 (only the pair that differs)", loads)
	}
}
