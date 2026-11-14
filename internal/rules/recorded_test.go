package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
)

func writeRecords(t *testing.T, es ...*exchange.Exchange) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "exchanges.ndjson")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range es {
		enc.Encode(e) //nolint:errcheck
	}
	f.Close()
	return p
}

func rec(id int, method, url string, status int, b string) *exchange.Exchange {
	return &exchange.Exchange{V: exchange.Version, ID: id, Method: method, URL: url, Status: status, Kind: "http",
		Response: &exchange.Message{Headers: exchange.Headers{}, Body: &body.Rendered{Size: int64(len(b)), Raw: body.NewRaw([]byte(b), false)}}}
}

func TestRecorded_LookupRoundRobin(t *testing.T) {
	p := writeRecords(t,
		rec(2, "GET", "https://api.example.com/items?page=2", 200, "second"),
		rec(1, "GET", "https://api.example.com/items?page=1", 200, "first"),
		rec(3, "POST", "https://api.example.com/items", 201, "created"),
		&exchange.Exchange{V: exchange.Version, ID: 4, Method: "GET", URL: "https://api.example.com/down", Kind: "http", Error: &exchange.Error{Kind: "refused"}},
	)
	r, err := LoadRecorded(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 3 {
		t.Errorf("Len = %d, want 3 (a failure has no response to serve)", r.Len())
	}
	// Paired by query parameter names, served in recorded order, wrapping.
	for _, want := range []int{1, 2, 1} {
		e := r.Lookup("GET", "api.example.com:443", "/items", "page=9")
		if e == nil || e.ID != want {
			t.Fatalf("got %v, want #%d", e, want)
		}
	}
	if r.Lookup("GET", "api.example.com", "/items", "") != nil {
		t.Error("matched without the query parameter")
	}
	if r.Lookup("GET", "other.com", "/items", "page=1") != nil {
		t.Error("matched another host")
	}
	r2, _ := LoadRecorded(p, true)
	if e := r2.Lookup("POST", "localhost:8080", "/items", ""); e == nil || e.ID != 3 {
		t.Errorf("ignoreHost lookup = %v", e)
	}
	var none *Recorded
	if none.Lookup("GET", "h", "/", "") != nil {
		t.Error("nil Recorded")
	}
}
