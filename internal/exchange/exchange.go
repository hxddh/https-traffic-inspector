// Package exchange defines httpmon's exchange record -- one HTTP exchange,
// request and response together -- which is both the --format json output
// and the format sessions keep, and renders it as a one-line summary.
package exchange

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
)

// Version is the schema version written in every record.
const Version = 3

// Exchange is one HTTP exchange, or one WebSocket connection.
type Exchange struct {
	V       int    `json:"v"`
	Session string `json:"session,omitempty"`
	ID      int    `json:"id"`
	Time    string `json:"time"`
	Kind    string `json:"kind"` // "http" or "websocket"

	Method string `json:"method"`
	URL    string `json:"url"`

	Status     int     `json:"status,omitempty"`
	StatusText string  `json:"status_text,omitempty"`
	DurationMs float64 `json:"duration_ms"`

	Request  Message  `json:"request"`
	Response *Message `json:"response,omitempty"`
	// Error is set, and Response is nil, when no response came.
	Error *Error `json:"error,omitempty"`

	GRPC      *GRPCStatus `json:"grpc,omitempty"`
	WebSocket *WebSocket  `json:"websocket,omitempty"`

	// Redacted marks a record made with --redact: credentials in headers and
	// the URL are masked, so requests that carried them cannot be replayed.
	Redacted bool `json:"redacted,omitempty"`

	// Rule names the --mock, --fault or --map rule that touched the
	// exchange, as written: "mock: GET */v1/orders => 500".
	Rule string `json:"rule,omitempty"`

	// Hint is a short error description found in a 4xx/5xx body, for the
	// summary line. It is not part of the record.
	Hint string `json:"-"`
}

// Message is one side of an exchange.
type Message struct {
	Proto    string         `json:"proto,omitempty"`
	Headers  Headers        `json:"headers"`
	Trailers Headers        `json:"trailers,omitempty"`
	Body     *body.Rendered `json:"body,omitempty"`
}

// Headers maps each header name to its values, in order.
type Headers map[string][]string

// FromHTTP copies h.
func FromHTTP(h http.Header) Headers {
	if len(h) == 0 {
		return Headers{}
	}
	out := make(Headers, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// HTTP converts back to an http.Header.
func (h Headers) HTTP() http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	return out
}

// Error describes why an exchange got no response.
type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// GRPCStatus is a gRPC call's outcome, from its trailers.
type GRPCStatus struct {
	Code    int    `json:"code"`
	Name    string `json:"name,omitempty"`
	Message string `json:"message,omitempty"`
}

// WebSocket holds the messages of an upgraded connection.
type WebSocket struct {
	Messages []WSMessage `json:"messages"`
	Dropped  int         `json:"dropped,omitempty"`
}

// WSMessage is one WebSocket message.
type WSMessage struct {
	From        string  `json:"from"` // "client" or "server"
	Time        string  `json:"time"`
	Type        string  `json:"type"`
	Size        int64   `json:"size"`
	Compressed  bool    `json:"compressed,omitempty"`
	Text        *string `json:"text,omitempty"`
	Base64      string  `json:"base64,omitempty"`
	Truncated   bool    `json:"truncated,omitempty"`
	CloseCode   int     `json:"close_code,omitempty"`
	CloseReason string  `json:"close_reason,omitempty"`
}

// Failed reports whether the exchange got no response.
func (e *Exchange) Failed() bool { return e.Error != nil }

// FormatTime is the timestamp format used in records.
func FormatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z07:00") }

// ---- summary ----

// SummaryLine renders e on one line:
//
//	#10 GET api.example.com/fail → 500 db_timeout (44ms, 105 B)
//	#11 GET 127.0.0.1:1/x → ERR refused (0ms)
//
// Untrusted text in it -- the URL, the error hint -- must be made safe by the
// caller for the medium it is written to.
func (e *Exchange) SummaryLine() string {
	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s %s → ", e.ID, e.Method, ShortURL(e.URL))
	dur := formatMs(e.DurationMs)
	switch {
	case e.Error != nil:
		fmt.Fprintf(&b, "ERR %s (%s)", e.Error.Kind, dur)
		if e.Error.Kind == "other" {
			fmt.Fprintf(&b, ": %s", clip(e.Error.Message, 80))
		}
	case e.WebSocket != nil:
		n := len(e.WebSocket.Messages) + e.WebSocket.Dropped
		fmt.Fprintf(&b, "%d websocket, %d messages (%s)", e.Status, n, dur)
	default:
		fmt.Fprintf(&b, "%d", e.Status)
		if e.GRPC != nil && e.GRPC.Code != 0 {
			fmt.Fprintf(&b, " grpc %s", e.GRPC.Name)
		}
		if e.Hint != "" {
			fmt.Fprintf(&b, " %s", e.Hint)
		}
		size := int64(0)
		if e.Response != nil && e.Response.Body != nil {
			size = e.Response.Body.Size
		}
		fmt.Fprintf(&b, " (%s, %s)", dur, formatSize(size))
	}
	if e.Rule != "" {
		kind, _, _ := strings.Cut(e.Rule, ":")
		fmt.Fprintf(&b, " [%s]", kind)
	}
	return b.String()
}

// maxSummaryQuery bounds the query string shown in a summary line. A
// pre-signed URL's query alone can run past a kilobyte; the whole URL is
// still in the record and in "query --id".
const maxSummaryQuery = 60

// ShortURL is u without its scheme and with a long query string cut short:
// "api.example.com/f?X-Amz-Algorithm=…(+1084 chars)".
func ShortURL(u string) string {
	u = stripScheme(u)
	path, query, ok := strings.Cut(u, "?")
	if !ok || len([]rune(query)) <= maxSummaryQuery {
		return u
	}
	// Keep whole parameters while they fit, so a cut never lands inside a
	// value -- or inside the marker of a masked one.
	params := strings.Split(query, "&")
	kept, n := 0, 0
	for kept < len(params) && n+len([]rune(params[kept]))+1 <= maxSummaryQuery {
		n += len([]rune(params[kept])) + 1
		kept++
	}
	if kept == 0 {
		// Even the first parameter is too long: keep its name if that fits,
		// else just the start of the query.
		q := []rune(query)
		if name, _, hasValue := strings.Cut(params[0], "="); hasValue && len([]rune(name)) < maxSummaryQuery {
			return fmt.Sprintf("%s?%s=…(+%d chars)", path, name, len(q)-len([]rune(name))-1)
		}
		return fmt.Sprintf("%s?%s…(+%d chars)", path, string(q[:maxSummaryQuery]), len(q)-maxSummaryQuery)
	}
	shown := strings.Join(params[:kept], "&")
	return fmt.Sprintf("%s?%s&…(+%d chars)", path, shown, len([]rune(query))-len([]rune(shown))-1)
}

func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		return u[i+3:]
	}
	return u
}

func formatMs(ms float64) string {
	switch {
	case ms >= 10000:
		return fmt.Sprintf("%.0fs", ms/1000)
	case ms >= 1000:
		return fmt.Sprintf("%.1fs", ms/1000)
	}
	return fmt.Sprintf("%.0fms", ms)
}

func formatSize(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n >= 10<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

func clip(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

// Pending is an exchange that had not finished when the run ended: the
// server never answered, or the command exited first.
type Pending struct {
	ID        int     `json:"id"`
	Method    string  `json:"method"`
	URL       string  `json:"url"`
	WaitingMs float64 `json:"waiting_ms"`
	// Status is set when the response had started -- its headers arrived --
	// but its body had not ended: a stream, or a stalled download.
	Status int `json:"status,omitempty"`
}

// SummaryLine renders p like a completed exchange's line.
func (p Pending) SummaryLine() string {
	if p.Status != 0 {
		return fmt.Sprintf("#%d %s %s → %d … body still open after %s", p.ID, p.Method, ShortURL(p.URL), p.Status, formatMs(p.WaitingMs))
	}
	return fmt.Sprintf("#%d %s %s → … no response after %s", p.ID, p.Method, ShortURL(p.URL), formatMs(p.WaitingMs))
}

// ---- digest ----

// Digest accumulates the end-of-run summary.
type Digest struct {
	Total      int            `json:"exchanges"`
	ByClass    map[string]int `json:"by_status"`
	Failed     int            `json:"failed"`
	Incomplete int            `json:"incomplete,omitempty"`
	SlowestID  int            `json:"slowest_id,omitempty"`
	SlowestMs  float64        `json:"slowest_ms,omitempty"`
	Matched    []int          `json:"fail_on_matched,omitempty"`
}

// Add counts e.
func (d *Digest) Add(e *Exchange) {
	if d.ByClass == nil {
		d.ByClass = map[string]int{}
	}
	d.Total++
	if e.Error != nil {
		d.Failed++
	} else if e.Status > 0 {
		d.ByClass[fmt.Sprintf("%dxx", e.Status/100)]++
	}
	// A WebSocket's duration is how long it stayed open, and a failure's how
	// long it took to fail: neither is a slow response.
	if e.WebSocket == nil && e.Error == nil && e.DurationMs > d.SlowestMs {
		d.SlowestMs, d.SlowestID = e.DurationMs, e.ID
	}
}

// String renders the digest on one line:
//
//	── 11 exchanges: 9×2xx, 1×5xx, 1 failed · slowest #5 45ms
func (d *Digest) String() string {
	var parts []string
	classes := make([]string, 0, len(d.ByClass))
	for c := range d.ByClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		parts = append(parts, fmt.Sprintf("%d×%s", d.ByClass[c], c))
	}
	if d.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", d.Failed))
	}
	if d.Incomplete > 0 {
		parts = append(parts, fmt.Sprintf("%d incomplete", d.Incomplete))
	}
	noun := "exchanges"
	if d.Total == 1 {
		noun = "exchange"
	}
	s := fmt.Sprintf("── %d %s", d.Total, noun)
	if len(parts) > 0 {
		s += ": " + strings.Join(parts, ", ")
	}
	if d.SlowestID > 0 {
		s += fmt.Sprintf(" · slowest #%d %s", d.SlowestID, formatMs(d.SlowestMs))
	}
	if len(d.Matched) > 0 {
		ids := make([]string, len(d.Matched))
		for i, id := range d.Matched {
			ids[i] = fmt.Sprintf("#%d", id)
		}
		s += " · --fail-on matched " + strings.Join(ids, ", ")
	}
	return s
}

// ---- reading records ----

// Reader reads exchanges from an NDJSON record.
type Reader struct {
	sc   *bufio.Scanner
	line int
}

// NewReader reads records from r.
func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 256*1024*1024)
	return &Reader{sc: sc}
}

// Next returns the next exchange, or io.EOF. A line that is not a v3
// exchange is an error; the caller may continue past it.
func (r *Reader) Next() (*Exchange, error) {
	for r.sc.Scan() {
		r.line++
		line := strings.TrimSpace(r.sc.Text())
		if line == "" {
			continue
		}
		var e Exchange
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", r.line, err)
		}
		if e.V != Version {
			return nil, fmt.Errorf("line %d: record version %d; this httpmon reads only version %d records", r.line, e.V, Version)
		}
		return &e, nil
	}
	if err := r.sc.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}
