package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
	"unicode/utf8"
)

// ── HAR types (HTTP Archive 1.2) ─────────────────────────────────────────────

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"_encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
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
	// Non-standard fields, prefixed "_" as the spec allows. Chrome DevTools
	// reads _error for a request that failed.
	Error    string         `json:"_error,omitempty"`
	Trailers []harNameValue `json:"_trailers,omitempty"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// harWSMessage is one WebSocket message in the form Chrome DevTools exports
// and imports.
type harWSMessage struct {
	Type   string  `json:"type"` // "send" or "receive"
	Time   float64 `json:"time"` // seconds since the epoch
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}

type harEntry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           struct{}       `json:"cache"`
	Timings         harTimings     `json:"timings"`
	ResourceType    string         `json:"_resourceType,omitempty"`
	WSMessages      []harWSMessage `json:"_webSocketMessages,omitempty"`
}

// harTruncatedComment marks a body HAR holds only a prefix of.
const harTruncatedComment = "httpmon: body truncated; only a prefix was captured"

// ── Writer ───────────────────────────────────────────────────────────────────
//
// Entries are written to the file as each exchange completes rather than held
// in memory until exit: memory stays flat in a long session, and if httpmon is
// killed the entries so far are on disk -- only the closing brackets are
// missing.

type harWriter struct {
	mu  sync.Mutex
	f   *os.File
	n   int
	err error

	// keep holds entries in memory as well; tests use it.
	keep bool
	kept []harEntry
}

var har *harWriter

// openHARFile creates path, readable by its owner only -- it holds whole
// request headers, Authorization values and cookies included -- and writes
// the HAR preamble.
func openHARFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// O_CREATE's mode does not apply to a file that already existed.
	if err := f.Chmod(0o600); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	creator, _ := json.Marshal(map[string]string{"name": "httpmon", "version": version})
	if _, err := fmt.Fprintf(f, "{\n  \"log\": {\n    \"version\": \"1.2\",\n    \"creator\": %s,\n    \"entries\": [", creator); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	har = &harWriter{f: f}
	return nil
}

func (w *harWriter) add(e harEntry) {
	if w == nil {
		return
	}
	b, err := json.MarshalIndent(e, "      ", "  ")
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.keep {
		w.kept = append(w.kept, e)
	}
	if w.err != nil || w.f == nil {
		return
	}
	if err != nil {
		w.err = err
		return
	}
	sep := ",\n      "
	if w.n == 0 {
		sep = "\n      "
	}
	if _, err := w.f.WriteString(sep); err != nil {
		w.err = err
		return
	}
	if _, err := w.f.Write(b); err != nil {
		w.err = err
		return
	}
	w.n++
}

// close writes the closing brackets and reports any error met while writing.
func (w *harWriter) close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return w.err
	}
	end := "\n    ]\n  }\n}\n"
	if w.n == 0 {
		end = "]\n  }\n}\n"
	}
	if _, err := w.f.WriteString(end); err != nil && w.err == nil {
		w.err = err
	}
	// Report close errors too: a failed flush here means truncated capture.
	if err := w.f.Close(); err != nil && w.err == nil {
		w.err = err
	}
	w.f = nil
	return w.err
}

// closeHAR finishes the HAR file.
func closeHAR() error {
	err := har.close()
	har = nil
	return err
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// harHeaders lists h in a stable order, repeated headers kept separately.
func harHeaders(h http.Header) []harNameValue {
	out := make([]harNameValue, 0, len(h))
	for _, k := range sortedKeys(h) {
		for _, v := range h[k] {
			out = append(out, harNameValue{Name: k, Value: v})
		}
	}
	return out
}

func harQueryString(rawURL string) []harNameValue {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return []harNameValue{}
	}
	vals, _ := url.ParseQuery(u.RawQuery)
	out := make([]harNameValue, 0, len(vals))
	for _, k := range sortedKeys(vals) {
		for _, v := range vals[k] {
			out = append(out, harNameValue{Name: k, Value: v})
		}
	}
	return out
}

// harText renders decoded body bytes for HAR: verbatim when they are text,
// base64 otherwise, as HAR's content.encoding allows.
func harText(b []byte) (text, encoding string) {
	if utf8.Valid(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func ms(d time.Duration) float64 { return millis(d) }

// ── Capture ──────────────────────────────────────────────────────────────────

// addHAREntry writes one completed exchange to the HAR file.
func addHAREntry(r capturedRequest, rs capturedResponse) {
	har.add(buildHAREntry(r, rs))
}

func buildHAREntry(r capturedRequest, rs capturedResponse) harEntry {
	rf, sf := r.facts, rs.facts
	// The same masking --record applies.
	reqURL := captureURL(rf.rawURL)

	var postData *harPostData
	if len(r.body.Raw) > 0 {
		mt := rf.headers.Get("Content-Type")
		if mt == "" {
			mt = "application/octet-stream"
		}
		dec, trunc := decodeContent(rf.headers.Get("Content-Encoding"), r.body.Raw, r.body.RawTruncated)
		text, enc := harText(dec)
		postData = &harPostData{MimeType: mt, Text: text, Encoding: enc}
		if trunc {
			postData.Comment = harTruncatedComment
		}
	}

	total := sf.totalDuration()
	e := harEntry{
		StartedDateTime: rf.startTime.UTC().Format(time.RFC3339Nano),
		Time:            ms(total),
		Request: harRequest{
			Method:      rf.method,
			URL:         reqURL,
			HTTPVersion: rf.proto,
			Headers:     harHeaders(captureHeaders(rf.headers)),
			QueryString: harQueryString(reqURL),
			Cookies:     []harNameValue{},
			PostData:    postData,
			HeadersSize: -1,
			BodySize:    r.body.Size,
		},
		Response: harResponse{
			Headers: []harNameValue{},
			Cookies: []harNameValue{},
			Content: harContent{MimeType: "x-unknown"},
			// -1: not known, as the spec requires.
			HeadersSize: -1,
			BodySize:    -1,
		},
		// The send phase is not measured separately; it is folded into wait.
		Timings: harTimings{Send: 0, Wait: ms(sf.duration), Receive: ms(total - sf.duration)},
	}

	if rs.err != nil {
		e.Response.Error = rs.err.Kind + ": " + rs.err.Message
		e.Timings = harTimings{Send: 0, Wait: ms(total), Receive: 0}
		return e
	}

	mt := sf.headers.Get("Content-Type")
	if mt == "" {
		mt = "application/octet-stream"
	}
	statusText := sf.statusText
	if len(statusText) > 4 {
		statusText = statusText[4:] // strip "NNN "
	}
	dec, trunc := decodeContent(sf.headers.Get("Content-Encoding"), rs.body.Raw, rs.body.RawTruncated)
	text, enc := harText(dec)
	e.Response = harResponse{
		Status:      sf.status,
		StatusText:  statusText,
		HTTPVersion: sf.proto,
		Headers:     harHeaders(captureHeaders(sf.headers)),
		Cookies:     []harNameValue{},
		Content: harContent{
			Size:     int64(len(dec)),
			MimeType: mt,
			Text:     text,
			Encoding: enc,
		},
		RedirectURL: sf.headers.Get("Location"),
		HeadersSize: -1,
		// The bytes that crossed the wire, before any Content-Encoding was
		// removed.
		BodySize: rs.body.Size,
		Trailers: harTrailers(captureHeaders(sf.trailers)),
	}
	if trunc {
		e.Response.Content.Comment = harTruncatedComment
	}

	if sf.upgraded {
		e.ResourceType = "websocket"
		e.Timings = harTimings{Send: 0, Wait: ms(sf.duration), Receive: 0}
		for _, m := range rs.ws {
			typ := "receive"
			if m.fromClient {
				typ = "send"
			}
			data := ""
			switch {
			case m.opcode == wsClose:
				data = m.closeReason
			case utf8.Valid(m.data) && !bytes.ContainsRune(m.data, 0):
				data = string(m.data)
			default:
				data = base64.StdEncoding.EncodeToString(m.data)
			}
			e.WSMessages = append(e.WSMessages, harWSMessage{
				Type: typ, Time: float64(m.at.UnixNano()) / 1e9, Opcode: int(m.opcode), Data: data,
			})
		}
	}
	return e
}

// harTrailers is harHeaders, omitted when there are none.
func harTrailers(h http.Header) []harNameValue {
	if len(h) == 0 {
		return nil
	}
	return harHeaders(h)
}
