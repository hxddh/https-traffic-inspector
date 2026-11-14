package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParse_Mock(t *testing.T) {
	r, err := Parse(KindMock, `POST api.example.com/v1/* => 503 {"error":"down"}`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 503 || string(r.Body) != `{"error":"down"}` || r.ContentType != "application/json" {
		t.Errorf("rule = %+v", r)
	}
	if !r.matches("POST", "api.example.com/v1/orders") || r.matches("GET", "api.example.com/v1/orders") {
		t.Error("method or pattern mismatch")
	}
	if r.matches("POST", "api.example.com/v2/orders") {
		t.Error("matched another path")
	}
	if r.Label() != `mock: POST api.example.com/v1/* => 503 {"error":"down"}` {
		t.Errorf("label = %q", r.Label())
	}
}

func TestParse_MockFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "body.json")
	os.WriteFile(p, []byte(`[1]`), 0o600) //nolint:errcheck
	r, err := Parse(KindMock, "*/x => 200 @"+p)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "[1]" || r.ContentType != "application/json" {
		t.Errorf("rule = %+v", r)
	}
}

func TestParse_HostOnlyPatternMatchesEveryPath(t *testing.T) {
	r, err := Parse(KindMock, "https://API.example.com => 204")
	if err != nil {
		t.Fatal(err)
	}
	if !r.matches("GET", "api.example.com/") || !r.matches("DELETE", "api.example.com/a/b") || r.matches("GET", "other.com/") {
		t.Error("host-only pattern")
	}
}

func TestParse_Fault(t *testing.T) {
	for _, tc := range []struct {
		in     string
		action string
		delay  time.Duration
		after  int64
		prob   float64
	}{
		{"* */slow => delay 2s", FaultDelay, 2 * time.Second, 0, 1},
		{"*/x => reset", FaultReset, 0, 0, 1},
		{"*/x => reset after 1KB 25%", FaultReset, 0, 1024, 0.25},
		{"GET h/x => timeout", FaultTimeout, 0, 0, 1},
	} {
		r, err := Parse(KindFault, tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if r.Action != tc.action || r.Delay != tc.delay || r.After != tc.after || r.Prob != tc.prob {
			t.Errorf("%s: %+v", tc.in, r)
		}
	}
}

func TestParse_Errors(t *testing.T) {
	for _, tc := range []struct{ kind, in, want string }{
		{KindMock, "*/x 500", "=>"},
		{KindMock, "*/x => abc", "status"},
		{KindMock, "a b c => 200", "METHOD"},
		{KindFault, "*/x => explode", "unknown fault"},
		{KindFault, "*/x => delay soon", "bad delay"},
		{KindFault, "*/x => reset 150%", "percentage"},
		{KindFault, "*/x => reset after lots", "bad size"},
		{KindMap, "a/b => c", "HOST"},
		{KindMap, "a => c/path", "bad target"},
		{KindMap, "a => http://localhost:80@evil.example", "bad target"},
		{"other", "a => b", "unknown rule kind"},
	} {
		_, err := Parse(tc.kind, tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%s, %q) = %v, want an error containing %q", tc.kind, tc.in, err, tc.want)
		}
	}
}

func TestSet_Decide(t *testing.T) {
	s, err := NewSet(
		[]string{"GET */mocked => 418"},
		[]string{"*/slow => delay 1s"},
		[]string{"old.example.com => https://new.example.com:8443", "db:5432 => localhost:15432"},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Decide("GET", "a.com", "/mocked")
	if d.Mock == nil || d.Fault != nil || d.Map != nil {
		t.Errorf("decision = %+v", d)
	}
	d = s.Decide("GET", "Old.Example.com:8080", "/slow")
	if d.Fault == nil || d.Map == nil || d.Map.To.Host != "new.example.com:8443" || d.Map.To.Scheme != "https" {
		t.Errorf("decision = %+v", d)
	}
	if d := s.Decide("GET", "db:5432", "/"); d.Map == nil || d.Map.To.Scheme != "http" {
		t.Errorf("port-specific map = %+v", d)
	}
	if d := s.Decide("GET", "db:5433", "/"); d.Map != nil {
		t.Error("a port-specific map matched another port")
	}
	// Rules added at run time take precedence.
	if err := s.Replace([]string{"GET */mocked => 500"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if d := s.Decide("GET", "a.com", "/mocked"); d.Mock.Status != 500 {
		t.Errorf("runtime rule not first: %d", d.Mock.Status)
	}
	if s.Empty() {
		t.Error("Empty")
	}
	var none *Set
	if !none.Empty() || none.Decide("GET", "h", "/").Mock != nil {
		t.Error("nil set")
	}
}

func TestSet_Probability(t *testing.T) {
	s, _ := NewSet(nil, []string{"*/x => reset 50%"}, nil)
	hits := 0
	for range 2000 {
		if s.Decide("GET", "h", "/x").Fault != nil {
			hits++
		}
	}
	if hits < 800 || hits > 1200 {
		t.Errorf("50%% fault fired %d of 2000 times", hits)
	}
}
