package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// ── HAR types (HTTP Archive 1.2) ─────────────────────────────────────────────

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	Cookies     []harNameValue `json:"cookies"`
	PostData    *harPostData   `json:"postData,omitempty"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
}

type harResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	Cookies     []harNameValue `json:"cookies"`
	Content     harContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
}

type harFile struct {
	Log struct {
		Version string     `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

// ── State ────────────────────────────────────────────────────────────────────

var (
	harEntries   []harEntry
	harEntriesMu sync.Mutex

	pendingHAR   = make(map[int]*harEntry)
	pendingHARMu sync.Mutex
)

// ── Helpers ──────────────────────────────────────────────────────────────────

func harHeaders(h http.Header) []harNameValue {
	out := make([]harNameValue, 0, len(h))
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, harNameValue{Name: k, Value: v})
		}
	}
	return out
}

func harQueryString(rawQuery string) []harNameValue {
	if rawQuery == "" {
		return []harNameValue{}
	}
	vals, _ := url.ParseQuery(rawQuery)
	out := make([]harNameValue, 0, len(vals))
	for k, vs := range vals {
		for _, v := range vs {
			out = append(out, harNameValue{Name: k, Value: v})
		}
	}
	return out
}

// ── Capture ──────────────────────────────────────────────────────────────────

func addHARRequest(reqID int, req *http.Request, body string, startTime time.Time) {
	var postData *harPostData
	bodySize := req.ContentLength
	if body != "" {
		mt := req.Header.Get("Content-Type")
		if mt == "" {
			mt = "application/octet-stream"
		}
		postData = &harPostData{MimeType: mt, Text: body}
	}

	e := &harEntry{
		StartedDateTime: startTime.UTC().Format(time.RFC3339Nano),
		Request: harRequest{
			Method:      req.Method,
			URL:         req.URL.String(),
			HTTPVersion: req.Proto,
			Headers:     harHeaders(req.Header),
			QueryString: harQueryString(req.URL.RawQuery),
			Cookies:     []harNameValue{},
			PostData:    postData,
			HeadersSize: -1,
			BodySize:    bodySize,
		},
	}

	pendingHARMu.Lock()
	pendingHAR[reqID] = e
	pendingHARMu.Unlock()
}

func addHARResponse(reqID int, resp *http.Response, body string, dur time.Duration) {
	pendingHARMu.Lock()
	e, ok := pendingHAR[reqID]
	if ok {
		delete(pendingHAR, reqID)
	}
	pendingHARMu.Unlock()
	if !ok {
		return
	}

	mt := resp.Header.Get("Content-Type")
	if mt == "" {
		mt = "application/octet-stream"
	}

	statusText := resp.Status
	if len(statusText) > 4 {
		statusText = statusText[4:] // strip "NNN "
	}

	ms := float64(dur) / float64(time.Millisecond)
	e.Time = ms
	e.Response = harResponse{
		Status:      resp.StatusCode,
		StatusText:  fmt.Sprintf("%s", statusText),
		HTTPVersion: resp.Proto,
		Headers:     harHeaders(resp.Header),
		Cookies:     []harNameValue{},
		Content: harContent{
			Size:     resp.ContentLength,
			MimeType: mt,
			Text:     body,
		},
		RedirectURL: resp.Header.Get("Location"),
		HeadersSize: -1,
		BodySize:    resp.ContentLength,
	}
	e.Timings = harTimings{Wait: ms}

	harEntriesMu.Lock()
	harEntries = append(harEntries, *e)
	harEntriesMu.Unlock()
}

// ── Output ───────────────────────────────────────────────────────────────────

// writeHARFile serialises all captured entries to path as HAR 1.2 JSON.
func writeHARFile(path string) error {
	harEntriesMu.Lock()
	entries := make([]harEntry, len(harEntries))
	copy(entries, harEntries)
	harEntriesMu.Unlock()

	if entries == nil {
		entries = []harEntry{}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var out harFile
	out.Log.Version = "1.2"
	out.Log.Creator.Name = "httpmon"
	out.Log.Creator.Version = "1.0"
	out.Log.Entries = entries

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
