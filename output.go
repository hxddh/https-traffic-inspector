package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- output channel ----
//
// httpmon's own output -- text blocks or NDJSON -- goes to stderr by default,
// so the wrapped command's stdout stays exactly what the command wrote and can
// be piped or redirected. -o/--output sends it to a file instead, and
// "--output -" to stdout, which is where 1.x wrote it.

var (
	// textOut receives text-mode output; tests swap it for a buffer.
	textOut   io.Writer = os.Stdout
	textOutMu sync.Mutex

	jsonEnc   = json.NewEncoder(os.Stdout)
	jsonEncMu sync.Mutex

	// useColor enables ANSI colour, only when output goes to a terminal.
	useColor bool
)

// setOutput directs httpmon's output to w.
func setOutput(w io.Writer) {
	swapTextOut(w)
	jsonEncMu.Lock()
	jsonEnc = json.NewEncoder(w)
	jsonEncMu.Unlock()
}

// swapTextOut replaces the text output writer and returns the previous one.
func swapTextOut(w io.Writer) io.Writer {
	textOutMu.Lock()
	defer textOutMu.Unlock()
	prev := textOut
	textOut = w
	return prev
}

// emitText writes one complete output block. Each block goes out under a
// single lock so concurrent exchanges never interleave inside one another.
func emitText(s string) {
	textOutMu.Lock()
	io.WriteString(textOut, s) //nolint:errcheck
	textOutMu.Unlock()
}

// emitJSON writes one NDJSON object.
func emitJSON(v any) {
	jsonEncMu.Lock()
	jsonEnc.Encode(v) //nolint:errcheck
	jsonEncMu.Unlock()
}

const (
	colCyan   = "36"
	colGreen  = "32"
	colYellow = "33"
	colRed    = "31"
	colBright = "93"
	colDim    = "2"
)

// paint wraps s in an ANSI colour when colour is enabled.
func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// ---- sinks ----

// sink renders exchange events. Exactly one is active, chosen by --format and
// --ui; --record and --har are fed separately, through captures.
//
// Every event carries its request number, and each sink is responsible for
// making untrusted text safe for its medium and for masking credentials.
type sink interface {
	requestHead(id int, f *requestFacts)
	requestBody(id int, f *requestFacts, b bodyView)
	responseHead(id int, f *responseFacts)
	responseBody(id int, f *responseFacts, b bodyView)
	// failed reports an exchange that got no response: the upstream could not
	// be reached, refused TLS, or reset the connection.
	failed(id int, f *requestFacts, err string, dur time.Duration)
	wsMessage(id int, m wsMessage)
	wsClosed(id int, s wsSummary)
	connect(target string)
	notice(msg string)
}

var (
	textOutput = textSink{}
	jsonOutput = jsonSink{}
)

// currentSink returns the sink for the active output mode.
func currentSink() sink {
	switch {
	case tuiMode:
		return tuiOutput
	case jsonMode:
		return jsonOutput
	default:
		return textOutput
	}
}

// noticef reports a diagnostic -- a TLS failure, a relayed tunnel -- through
// the active sink. In the TUI it appears on the status line instead of being
// written over the screen.
func noticef(format string, args ...any) {
	currentSink().notice(fmt.Sprintf(format, args...))
}

// ---- text ----

type textSink struct{}

func endLine(id int) string {
	return paint(colDim, fmt.Sprintf("%s #%d end", strings.Repeat("-", 52), id)) + "\n"
}

func writeHeaderBlock(b *strings.Builder, h map[string][]string) {
	for _, k := range sortedKeys(h) {
		fmt.Fprintf(b, "  %s: %s\n", sanitizeLine(k), sanitizeLine(strings.Join(h[k], ", ")))
	}
}

func (textSink) requestHead(id int, f *requestFacts) {
	var b strings.Builder
	b.WriteString("\n" + paint(colCyan, fmt.Sprintf("=== REQUEST #%d ===", id)) + "\n")
	fmt.Fprintf(&b, "Time: %s\n", f.startTime.Format("15:04:05"))
	fmt.Fprintf(&b, "%s %s %s\n", sanitizeLine(f.method), sanitizeLine(displayURL(f.rawURL)), f.proto)
	fmt.Fprintf(&b, "Host: %s\n", sanitizeLine(f.host))

	if strings.Contains(f.host, ".amazonaws.com") {
		writeS3Info(&b, f.host, f.path)
	}

	if f.rawQuery != "" {
		b.WriteString("\nQuery Parameters:\n")
		params, _ := url.ParseQuery(f.rawQuery)
		for _, k := range sortedKeys(params) {
			v := strings.Join(params[k], ", ")
			if !showSecrets && sensitiveQueryParams[strings.ToLower(k)] {
				v = maskToken(v)
			}
			fmt.Fprintf(&b, "  %s: %s\n", sanitizeLine(k), sanitizeLine(v))
		}
	}

	b.WriteString("\nHeaders:\n")
	writeHeaderBlock(&b, displayHeaders(f.headers))
	b.WriteString("\n")
	emitText(b.String())
}

func (textSink) requestBody(id int, f *requestFacts, v bodyView) {
	if s := truncateForDisplay(v); s != "" {
		emitText("\n" + paint(colCyan, fmt.Sprintf("--- REQUEST #%d body ---", id)) + "\n" + sanitizeTerminal(s) + "\n\n")
	}
}

func (textSink) responseHead(id int, f *responseFacts) {
	var b strings.Builder
	b.WriteString("\n" + paint(colGreen, fmt.Sprintf("=== RESPONSE #%d ===", id)) + "\n")
	fmt.Fprintf(&b, "%s %s (%s)\n", f.proto, sanitizeLine(f.statusText), f.duration.Round(time.Millisecond))
	b.WriteString("\nHeaders:\n")
	writeHeaderBlock(&b, displayHeaders(f.headers))
	emitText(b.String())
}

func (textSink) responseBody(id int, f *responseFacts, v bodyView) {
	var b strings.Builder
	if s := truncateForDisplay(v); s != "" {
		b.WriteString("\n" + paint(colGreen, fmt.Sprintf("--- RESPONSE #%d body ---", id)) + "\n" + sanitizeTerminal(s) + "\n")
	}
	if len(f.trailers) > 0 {
		b.WriteString("\nTrailers:\n")
		writeHeaderBlock(&b, displayHeaders(f.trailers))
	}
	if st := grpcStatusLine(f.headers, f.trailers); st != "" {
		fmt.Fprintf(&b, "\n%s\n", sanitizeLine(st))
	}
	if f.upgraded {
		// A WebSocket: its messages follow, and its end is reported on close.
		emitText(b.String())
		return
	}
	b.WriteString("\n" + endLine(id))
	emitText(b.String())
}

func (textSink) failed(id int, f *requestFacts, err string, dur time.Duration) {
	var b strings.Builder
	b.WriteString("\n" + paint(colRed, fmt.Sprintf("=== RESPONSE #%d FAILED (%s) ===", id, dur.Round(time.Millisecond))) + "\n")
	b.WriteString(sanitizeTerminal(err) + "\n\n")
	b.WriteString(endLine(id))
	emitText(b.String())
}

func (textSink) wsMessage(id int, m wsMessage) {
	var b strings.Builder
	b.WriteString("\n" + paint(colCyan, fmt.Sprintf("--- WS #%d %s %s ---", id, m.direction(), m.describe())) + "\n")
	if s := m.displayText(); s != "" {
		b.WriteString(sanitizeTerminal(s) + "\n")
	}
	emitText(b.String())
}

func (textSink) wsClosed(id int, s wsSummary) {
	emitText("\n" + paint(colGreen, fmt.Sprintf("=== WS #%d closed: %s ===", id, s.describe())) + "\n\n" + endLine(id))
}

func (textSink) connect(target string) {
	emitText("\n" + paint(colYellow, fmt.Sprintf("=== CONNECT %s ===", sanitizeLine(target))) + "\n\n")
}

func (textSink) notice(msg string) {
	fmt.Fprintf(os.Stderr, "httpmon: %s\n", sanitizeLine(msg))
}

func writeS3Info(b *strings.Builder, host, path string) {
	host, _, _ = strings.Cut(host, ":")
	// virtual-hosted style: <bucket>.s3[.<region>].amazonaws.com/<key>
	if idx := strings.Index(host, ".s3."); idx > 0 {
		b.WriteString(paint(colBright, "S3 Bucket: "+sanitizeLine(host[:idx])) + "\n")
		if key := strings.TrimPrefix(path, "/"); key != "" {
			b.WriteString(paint(colBright, "S3 Key/Prefix: "+sanitizeLine(key)) + "\n")
		}
		return
	}
	// path-style: s3[.<region>].amazonaws.com/<bucket>/<key>
	pathParts := strings.SplitN(path, "/", 3)
	if len(pathParts) >= 2 && pathParts[1] != "" {
		b.WriteString(paint(colBright, "S3 Bucket: "+sanitizeLine(pathParts[1])) + "\n")
		if len(pathParts) > 2 && pathParts[2] != "" {
			b.WriteString(paint(colBright, "S3 Key/Prefix: "+sanitizeLine(pathParts[2])) + "\n")
		}
	}
}

// ---- JSON ----

type jsonSink struct{}

type jsonRequest struct {
	ID        int               `json:"id"`
	Time      string            `json:"time"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Proto     string            `json:"proto"`
	Host      string            `json:"host"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	Truncated bool              `json:"body_truncated,omitempty"`
}

type jsonResponse struct {
	ReqID      int               `json:"req_id"`
	Status     int               `json:"status"`
	Proto      string            `json:"proto"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	Truncated  bool              `json:"body_truncated,omitempty"`
	DurationMs int64             `json:"duration_ms"`
	// Trailers follow the body; gRPC reports its status here.
	Trailers map[string]string `json:"trailers,omitempty"`
}

type jsonFailure struct {
	ReqID      int    `json:"req_id"`
	Error      string `json:"error"`
	DurationMs int64  `json:"duration_ms"`
}

type jsonWSMessage struct {
	ReqID       int    `json:"req_id"`
	WS          string `json:"ws"` // "client" or "server": who sent it
	Type        string `json:"type"`
	Size        int64  `json:"size"` // payload bytes on the wire
	Compressed  bool   `json:"compressed,omitempty"`
	Data        string `json:"data,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	CloseCode   int    `json:"close_code,omitempty"`
	CloseReason string `json:"close_reason,omitempty"`
}

type jsonWSClosed struct {
	ReqID      int   `json:"req_id"`
	WSClosed   bool  `json:"ws_closed"`
	Messages   int   `json:"messages"`
	DurationMs int64 `json:"duration_ms"`
}

func (jsonSink) requestHead(int, *requestFacts) {} // one object per request, at body time

func (jsonSink) requestBody(id int, f *requestFacts, v bodyView) {
	emitJSON(jsonRequest{
		ID:        id,
		Time:      f.startTime.Format(time.RFC3339Nano),
		Method:    f.method,
		URL:       displayURL(f.rawURL),
		Proto:     f.proto,
		Host:      f.host,
		Headers:   flattenHeaders(displayHeaders(f.headers)),
		Body:      truncateForDisplay(v),
		Truncated: v.Truncated || len(v.Text) > displayMaxBody,
	})
}

func (jsonSink) responseHead(int, *responseFacts) {} // one object per response, at body time

func (jsonSink) responseBody(id int, f *responseFacts, v bodyView) {
	var trailers map[string]string
	if len(f.trailers) > 0 {
		trailers = flattenHeaders(displayHeaders(f.trailers))
	}
	emitJSON(jsonResponse{
		ReqID:      id,
		Status:     f.status,
		Proto:      f.proto,
		Headers:    flattenHeaders(displayHeaders(f.headers)),
		Body:       truncateForDisplay(v),
		Truncated:  v.Truncated || len(v.Text) > displayMaxBody,
		DurationMs: f.duration.Milliseconds(),
		Trailers:   trailers,
	})
}

func (jsonSink) failed(id int, _ *requestFacts, err string, dur time.Duration) {
	emitJSON(jsonFailure{ReqID: id, Error: err, DurationMs: dur.Milliseconds()})
}

func (jsonSink) wsMessage(id int, m wsMessage) {
	emitJSON(jsonWSMessage{
		ReqID: id, WS: m.sender(), Type: m.typeName(), Size: m.size, Compressed: m.compressed,
		Data: m.displayText(), Truncated: m.truncated,
		CloseCode: m.closeCode, CloseReason: m.closeReason,
	})
}

func (jsonSink) wsClosed(id int, s wsSummary) {
	emitJSON(jsonWSClosed{ReqID: id, WSClosed: true, Messages: s.messages, DurationMs: s.duration.Milliseconds()})
}

func (jsonSink) connect(string) {}

func (jsonSink) notice(msg string) {
	fmt.Fprintf(os.Stderr, "httpmon: %s\n", sanitizeLine(msg))
}
