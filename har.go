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
	Comment  string `json:"comment,omitempty"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Comment  string `json:"comment,omitempty"`
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
)

// harTruncatedComment marks a body HAR holds only a prefix of.
const harTruncatedComment = "httpmon: body truncated; only a prefix was captured"

func truncatedComment(v bodyView) string {
	if v.Truncated {
		return harTruncatedComment
	}
	return ""
}

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

// addHAREntry appends one completed exchange to the HAR log.
func addHAREntry(r capturedRequest, rs capturedResponse) {
	rf, sf := r.facts, rs.facts

	var postData *harPostData
	if r.body.Text != "" {
		mt := rf.headers.Get("Content-Type")
		if mt == "" {
			mt = "application/octet-stream"
		}
		postData = &harPostData{MimeType: mt, Text: r.body.Text, Comment: truncatedComment(r.body)}
	}

	var rawQuery string
	if u, err := url.Parse(rf.rawURL); err == nil {
		rawQuery = u.RawQuery
	}

	mt := sf.headers.Get("Content-Type")
	if mt == "" {
		mt = "application/octet-stream"
	}

	statusText := sf.statusText
	if len(statusText) > 4 {
		statusText = statusText[4:] // strip "NNN "
	}

	// content.size is the decoded size; bodySize is the bytes actually
	// transferred, which is only known from Content-Length. -1 means unknown,
	// as required by the HAR 1.2 spec.
	bodySize := sf.contentLength
	if bodySize < 0 {
		bodySize = -1
	}

	ms := float64(sf.duration) / float64(time.Millisecond)
	e := harEntry{
		StartedDateTime: rf.startTime.UTC().Format(time.RFC3339Nano),
		Time:            ms,
		Request: harRequest{
			Method:      rf.method,
			URL:         rf.rawURL,
			HTTPVersion: rf.proto,
			Headers:     harHeaders(rf.headers),
			QueryString: harQueryString(rawQuery),
			Cookies:     []harNameValue{},
			PostData:    postData,
			HeadersSize: -1,
			BodySize:    int64(len(r.body.Text)),
		},
		Response: harResponse{
			Status:      sf.status,
			StatusText:  statusText,
			HTTPVersion: sf.proto,
			Headers:     harHeaders(sf.headers),
			Cookies:     []harNameValue{},
			Content: harContent{
				Size:     int64(len(rs.body.Text)),
				MimeType: mt,
				Text:     rs.body.Text,
				Comment:  truncatedComment(rs.body),
			},
			RedirectURL: sf.headers.Get("Location"),
			HeadersSize: -1,
			BodySize:    bodySize,
		},
		// httpmon measures only the total round trip; send/receive are not
		// separable here, and -1 is the spec's "not applicable" value.
		Timings: harTimings{Send: -1, Wait: ms, Receive: -1},
	}

	harEntriesMu.Lock()
	harEntries = append(harEntries, e)
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
