package main

import (
	"net/http"
	"testing"

	"github.com/hxddh/https-traffic-inspector/v3/internal/body"
	"github.com/hxddh/https-traffic-inspector/v3/internal/exchange"
)

// useMemoryHAR routes HAR entries to memory for the duration of a test.
func useMemoryHAR(t *testing.T) *harWriter {
	t.Helper()
	saved, savedHM, savedCaptures := har, harMode, captures
	har, harMode, captures = &harWriter{keep: true}, true, newExchangeJoiner()
	t.Cleanup(func() { har, harMode, captures = saved, savedHM, savedCaptures })
	return har
}

// entries returns the HAR entries written so far.
func (w *harWriter) entries() []harEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]harEntry(nil), w.kept...)
}

// harFile is the shape of a HAR file, for reading one back.
type harFile struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

// writeHARForTest writes entries to a HAR file the way a run does.
func writeHARForTest(path string, entries ...harEntry) error {
	saved := har
	defer func() { har = saved }()
	if err := openHARFile(path); err != nil {
		return err
	}
	for _, e := range entries {
		har.add(e)
	}
	return closeHAR()
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
