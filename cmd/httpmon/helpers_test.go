package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
)

// memRecorder keeps a test's session records in memory.
type memRecorder struct{ buf bytes.Buffer }

// useMemoryHAR records exchanges to memory for the duration of a test; its
// entries are read back as HAR, the form most tests check.
func useMemoryHAR(t *testing.T) *memRecorder {
	t.Helper()
	m := &memRecorder{}
	recordMu.Lock()
	savedEnc, savedMode, savedCaptures := recordEncoder, recordMode, captures
	recordEncoder, recordMode, captures = json.NewEncoder(&m.buf), true, newExchangeJoiner()
	recordMu.Unlock()
	t.Cleanup(func() {
		recordMu.Lock()
		recordEncoder, recordMode, captures = savedEnc, savedMode, savedCaptures
		recordMu.Unlock()
	})
	return m
}

// exchanges returns the records written so far.
func (m *memRecorder) exchanges() []*exchange.Exchange {
	recordMu.Lock()
	data := append([]byte(nil), m.buf.Bytes()...)
	recordMu.Unlock()
	var out []*exchange.Exchange
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var e exchange.Exchange
		if dec.Decode(&e) != nil {
			return out
		}
		out = append(out, &e)
	}
}

// entries returns the records written so far, as HAR entries.
func (m *memRecorder) entries() []exchange.HAREntry {
	var out []exchange.HAREntry
	for _, e := range m.exchanges() {
		out = append(out, exchange.ToHAR(e))
	}
	return out
}

// harFile is the shape of a HAR file, for reading one back.
type harFile struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []exchange.HAREntry `json:"entries"`
	} `json:"log"`
}

// writeHARForTest writes entries to a HAR file as query --format har does.
func writeHARForTest(path string, entries ...exchange.HAREntry) error {
	var h exchange.HARLog
	h.Log.Version = "1.2"
	h.Log.Creator = map[string]string{"name": "httpmon", "version": version}
	h.Log.Entries = append([]exchange.HAREntry{}, entries...)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// recordedExchange describes a recorded exchange compactly for tests;
// writeRecording stores it as a v3 record.
type recordedExchange struct {
	ID                int
	Time              string
	Method            string
	URL               string
	ReqHeaders        map[string]string
	ReqBody           string
	ReqBodyTruncated  bool
	Status            int
	StatusText        string
	RespHeaders       map[string]string
	RespBody          string
	RespBodyTruncated bool
	RespTrailers      map[string]string
	DurationMs        int64
}

func headersOf(m map[string]string) exchange.Headers {
	h := exchange.Headers{}
	for k, v := range m {
		h[http.CanonicalHeaderKey(k)] = []string{v}
	}
	return h
}

func (r recordedExchange) v3() *exchange.Exchange {
	e := &exchange.Exchange{
		V: exchange.Version, Session: "test", ID: r.ID, Time: r.Time, Kind: "http",
		Method: r.Method, URL: r.URL, Status: r.Status, StatusText: r.StatusText,
		DurationMs: float64(r.DurationMs),
		Request:    exchange.Message{Headers: headersOf(r.ReqHeaders)},
		Response:   &exchange.Message{Headers: headersOf(r.RespHeaders)},
	}
	if r.ReqBody != "" {
		e.Request.Body = &body.Rendered{Size: int64(len(r.ReqBody)), Raw: &body.Raw{Encoding: "utf8", Data: r.ReqBody, Truncated: r.ReqBodyTruncated}}
	}
	if r.RespBody != "" {
		e.Response.Body = &body.Rendered{Size: int64(len(r.RespBody)), Raw: &body.Raw{Encoding: "utf8", Data: r.RespBody, Truncated: r.RespBodyTruncated},
			ContentEncoding: r.RespHeaders["Content-Encoding"]}
	}
	if len(r.RespTrailers) > 0 {
		e.Response.Trailers = headersOf(r.RespTrailers)
	}
	return e
}

func must[T any](v T, _ bool) T { return v }
