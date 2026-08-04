package main

import (
	"encoding/json"
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
		Version string `json:"version"`
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

func addHARRequest(reqID int, f requestFacts, body string, startTime time.Time) {
	var postData *harPostData
	if body != "" {
		mt := f.headers.Get("Content-Type")
		if mt == "" {
			mt = "application/octet-stream"
		}
		postData = &harPostData{MimeType: mt, Text: body}
	}

	var rawQuery string
	if u, err := url.Parse(f.rawURL); err == nil {
		rawQuery = u.RawQuery
	}

	e := &harEntry{
		StartedDateTime: startTime.UTC().Format(time.RFC3339Nano),
		Request: harRequest{
			Method:      f.method,
			URL:         f.rawURL,
			HTTPVersion: f.proto,
			Headers:     harHeaders(f.headers),
			QueryString: harQueryString(rawQuery),
			Cookies:     []harNameValue{},
			PostData:    postData,
			HeadersSize: -1,
			BodySize:    int64(len(body)),
		},
	}

	pendingHARMu.Lock()
	pendingHAR[reqID] = e
	pendingHARMu.Unlock()
}

func addHARResponse(reqID int, f responseFacts, body string) {
	pendingHARMu.Lock()
	e, ok := pendingHAR[reqID]
	if ok {
		delete(pendingHAR, reqID)
	}
	pendingHARMu.Unlock()
	if !ok {
		return
	}

	mt := f.headers.Get("Content-Type")
	if mt == "" {
		mt = "application/octet-stream"
	}

	statusText := f.statusText
	if len(statusText) > 4 {
		statusText = statusText[4:] // strip "NNN "
	}

	// content.size is the decoded size; bodySize is the bytes actually
	// transferred, which is only known from Content-Length. -1 means unknown,
	// as required by the HAR 1.2 spec.
	contentSize := int64(len(body))
	bodySize := f.contentLength
	if bodySize < 0 {
		bodySize = -1
	}

	ms := float64(f.duration) / float64(time.Millisecond)
	e.Time = ms
	e.Response = harResponse{
		Status:      f.status,
		StatusText:  statusText,
		HTTPVersion: f.proto,
		Headers:     harHeaders(f.headers),
		Cookies:     []harNameValue{},
		Content: harContent{
			Size:     contentSize,
			MimeType: mt,
			Text:     body,
		},
		RedirectURL: f.headers.Get("Location"),
		HeadersSize: -1,
		BodySize:    bodySize,
	}
	// httpmon measures only the total round trip; send/receive are not
	// separable here, and -1 is the spec's "not applicable" value.
	e.Timings = harTimings{Send: -1, Wait: ms, Receive: -1}

	harEntriesMu.Lock()
	harEntries = append(harEntries, *e)
	harEntriesMu.Unlock()
}

// ── Output ───────────────────────────────────────────────────────────────────

// writeHARFile serialises all captured entries to path as HAR 1.2 JSON.
func writeHARFile(path string) error {
	harEntriesMu.Lock()
	// make() never returns nil, so this always marshals as [] rather than null.
	entries := make([]harEntry, len(harEntries))
	copy(entries, harEntries)
	harEntriesMu.Unlock()

	f, err := os.Create(path)
	if err != nil {
		return err
	}

	var out harFile
	out.Log.Version = "1.2"
	out.Log.Creator.Name = "httpmon"
	out.Log.Creator.Version = version
	out.Log.Entries = entries

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		f.Close() //nolint:errcheck // the encode error is the one worth reporting
		return err
	}
	// Report close errors too: a failed flush here means truncated capture.
	return f.Close()
}
