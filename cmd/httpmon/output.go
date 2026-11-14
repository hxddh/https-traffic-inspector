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

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/textsafe"
)

// ---- output channel ----
//
// httpmon's own output goes to stderr by default, so the wrapped command's
// stdout stays exactly what the command wrote and can be piped or redirected.
// -o/--output sends it to a file instead, and "-o -" to stdout.

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
// --ui; sessions are fed separately, through captures.
//
// The text and TUI sinks show each exchange as it unfolds, from the events
// before the last; the summary and JSON sinks report each exchange once, when
// it completes. Every sink makes untrusted text safe for its medium and
// masks credentials.
type sink interface {
	requestHead(id int, f *requestFacts)
	requestBody(id int, f *requestFacts, b bodyView)
	responseHead(id int, f *responseFacts)
	responseBody(id int, f *responseFacts, b bodyView)
	// failed reports an exchange that got no response: the upstream could not
	// be reached, refused TLS, or reset the connection.
	failed(id int, f *requestFacts, err *exchange.Error, dur time.Duration)
	wsMessage(id int, m wsMessage)
	wsClosed(id int, s wsSummary)
	// exchange reports a completed exchange.
	exchange(e *exchange.Exchange)
	// incomplete reports, at the end of the run, an exchange still waiting.
	incomplete(p exchange.Pending)
	connect(target string)
	notice(msg string)
	// start and end bracket the run.
	start(info runInfo)
	end(d *exchange.Digest)
}

// runInfo describes a run for the start of the output.
type runInfo struct {
	Version string   `json:"version"`
	Proxy   string   `json:"proxy"`
	Command []string `json:"command,omitempty"`
	Filter  string   `json:"filter,omitempty"`
	CA      string   `json:"ca_bundle"`
	Session string   `json:"session,omitempty"`
}

var (
	textOutput    = textSink{}
	jsonOutput    = jsonSink{}
	summaryOutput = summarySink{}
)

// currentSink returns the sink for the active output mode.
func currentSink() sink {
	switch {
	case tuiMode:
		return tuiOutput
	case jsonMode:
		return jsonOutput
	case summaryMode:
		return summaryOutput
	default:
		return textOutput
	}
}

// noticef reports a diagnostic -- a TLS failure, a relayed tunnel -- through
// the active sink. In the TUI it appears on the status line instead of being
// written over the screen; in JSON it is an event in the stream.
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
		fmt.Fprintf(b, "  %s: %s\n", textsafe.Line(k), textsafe.Line(strings.Join(h[k], ", ")))
	}
}

// bodyPrefix starts every line of untrusted content in text output. httpmon's
// own headings start at the first column and content never does, so a body
// cannot forge a heading -- a fake "=== RESPONSE #9 ===" shows up indented,
// as part of the body it came in.
const bodyPrefix = "│ "

// quoteBody makes s safe for the terminal and prefixes each of its lines.
func quoteBody(s string) string {
	s = textsafe.Terminal(s)
	return bodyPrefix + strings.ReplaceAll(s, "\n", "\n"+bodyPrefix)
}

func (textSink) requestHead(id int, f *requestFacts) {
	var b strings.Builder
	b.WriteString("\n" + paint(colCyan, fmt.Sprintf("=== REQUEST #%d ===", id)) + "\n")
	fmt.Fprintf(&b, "Time: %s\n", f.startTime.Format("15:04:05"))
	fmt.Fprintf(&b, "%s %s %s\n", textsafe.Line(f.method), textsafe.Line(displayURL(f.rawURL)), f.proto)
	fmt.Fprintf(&b, "Host: %s\n", textsafe.Line(f.host))

	if strings.Contains(f.host, ".amazonaws.com") {
		writeS3Info(&b, f.host, f.path)
	}

	if f.rawQuery != "" {
		b.WriteString("\nQuery Parameters:\n")
		params, _ := url.ParseQuery(f.rawQuery)
		for _, k := range sortedKeys(params) {
			v := strings.Join(params[k], ", ")
			if !showSecrets && textsafe.IsSensitiveParam(k) {
				v = textsafe.MaskToken(v)
			}
			fmt.Fprintf(&b, "  %s: %s\n", textsafe.Line(k), textsafe.Line(v))
		}
	}

	b.WriteString("\nHeaders:\n")
	writeHeaderBlock(&b, displayHeaders(f.headers))
	b.WriteString("\n")
	emitText(b.String())
}

func (textSink) requestBody(id int, f *requestFacts, v bodyView) {
	if s := truncateForDisplay(v); s != "" {
		emitText("\n" + paint(colCyan, fmt.Sprintf("--- REQUEST #%d body ---", id)) + "\n" + quoteBody(s) + "\n\n")
	}
}

func (textSink) responseHead(id int, f *responseFacts) {
	var b strings.Builder
	b.WriteString("\n" + paint(colGreen, fmt.Sprintf("=== RESPONSE #%d ===", id)) + "\n")
	fmt.Fprintf(&b, "%s %s (%s)\n", f.proto, textsafe.Line(f.statusText), f.duration.Round(time.Millisecond))
	b.WriteString("\nHeaders:\n")
	writeHeaderBlock(&b, displayHeaders(f.headers))
	emitText(b.String())
}

func (textSink) responseBody(id int, f *responseFacts, v bodyView) {
	var b strings.Builder
	if s := truncateForDisplay(v); s != "" {
		b.WriteString("\n" + paint(colGreen, fmt.Sprintf("--- RESPONSE #%d body ---", id)) + "\n" + quoteBody(s) + "\n")
	}
	if len(f.trailers) > 0 {
		b.WriteString("\nTrailers:\n")
		writeHeaderBlock(&b, displayHeaders(f.trailers))
	}
	if st := body.GRPCStatusLine(f.headers, f.trailers); st != "" {
		fmt.Fprintf(&b, "\n%s\n", textsafe.Line(st))
	}
	if f.upgraded {
		// A WebSocket: its messages follow, and its end is reported on close.
		emitText(b.String())
		return
	}
	b.WriteString("\n" + endLine(id))
	emitText(b.String())
}

func (textSink) failed(id int, f *requestFacts, err *exchange.Error, dur time.Duration) {
	var b strings.Builder
	b.WriteString("\n" + paint(colRed, fmt.Sprintf("=== RESPONSE #%d FAILED: %s (%s) ===", id, err.Kind, dur.Round(time.Millisecond))) + "\n")
	b.WriteString(textsafe.Terminal(err.Message) + "\n\n")
	b.WriteString(endLine(id))
	emitText(b.String())
}

func (textSink) wsMessage(id int, m wsMessage) {
	var b strings.Builder
	b.WriteString("\n" + paint(colCyan, fmt.Sprintf("--- WS #%d %s %s ---", id, m.direction(), m.describe())) + "\n")
	if s := m.displayText(); s != "" {
		b.WriteString(quoteBody(s) + "\n")
	}
	emitText(b.String())
}

func (textSink) wsClosed(id int, s wsSummary) {
	emitText("\n" + paint(colGreen, fmt.Sprintf("=== WS #%d closed: %s ===", id, s.describe())) + "\n\n" + endLine(id))
}

func (textSink) exchange(*exchange.Exchange) {} // shown as it unfolded

func (textSink) incomplete(p exchange.Pending) {
	emitText("\n" + paint(colYellow, textsafe.Line(p.SummaryLine())) + "\n")
}

func (textSink) connect(target string) {
	emitText("\n" + paint(colYellow, fmt.Sprintf("=== CONNECT %s ===", textsafe.Line(target))) + "\n\n")
}

func (textSink) notice(msg string) {
	fmt.Fprintf(os.Stderr, "httpmon: %s\n", textsafe.Line(msg))
}

func (textSink) start(info runInfo) {
	if len(info.Command) == 0 {
		return // httpmon proxy prints its own banner
	}
	printBanner(info)
}

func (textSink) end(d *exchange.Digest) {
	emitText("\n" + textsafe.Line(d.String()) + "\n")
}

// printBanner writes the startup lines to stderr: they are diagnostics, not
// output, whatever -o says.
func printBanner(info runInfo) {
	var b strings.Builder
	fmt.Fprintf(&b, "httpmon %s: proxy on %s, CA bundle %s\n", info.Version, info.Proxy, info.CA)
	if info.Filter != "" {
		fmt.Fprintf(&b, "httpmon: filter %q\n", info.Filter)
	}
	if insecureUpstream {
		b.WriteString("httpmon: upstream TLS verification DISABLED (--insecure-upstream)\n")
	}
	if len(info.Command) > 0 {
		fmt.Fprintf(&b, "httpmon: running %s\n", strings.Join(info.Command, " "))
	}
	if info.Session != "" {
		fmt.Fprintf(&b, "httpmon: session %s\n", info.Session)
	}
	fmt.Fprint(os.Stderr, b.String())
}

func writeS3Info(b *strings.Builder, host, path string) {
	host, _, _ = strings.Cut(host, ":")
	// virtual-hosted style: <bucket>.s3[.<region>].amazonaws.com/<key>
	if idx := strings.Index(host, ".s3."); idx > 0 {
		b.WriteString(paint(colBright, "S3 Bucket: "+textsafe.Line(host[:idx])) + "\n")
		if key := strings.TrimPrefix(path, "/"); key != "" {
			b.WriteString(paint(colBright, "S3 Key/Prefix: "+textsafe.Line(key)) + "\n")
		}
		return
	}
	// path-style: s3[.<region>].amazonaws.com/<bucket>/<key>
	pathParts := strings.SplitN(path, "/", 3)
	if len(pathParts) >= 2 && pathParts[1] != "" {
		b.WriteString(paint(colBright, "S3 Bucket: "+textsafe.Line(pathParts[1])) + "\n")
		if len(pathParts) > 2 && pathParts[2] != "" {
			b.WriteString(paint(colBright, "S3 Key/Prefix: "+textsafe.Line(pathParts[2])) + "\n")
		}
	}
}

// ---- summary ----

// summarySink writes one line per completed exchange and a digest at the end:
// the overview an agent needs, at a small fraction of the full output's size.
// Details are one "httpmon query" away.
type summarySink struct{}

func (summarySink) requestHead(int, *requestFacts)                            {}
func (summarySink) requestBody(int, *requestFacts, bodyView)                  {}
func (summarySink) responseHead(int, *responseFacts)                          {}
func (summarySink) responseBody(int, *responseFacts, bodyView)                {}
func (summarySink) failed(int, *requestFacts, *exchange.Error, time.Duration) {}
func (summarySink) wsMessage(int, wsMessage)                                  {}
func (summarySink) wsClosed(int, wsSummary)                                   {}
func (summarySink) connect(string)                                            {}

func (summarySink) exchange(e *exchange.Exchange) {
	emitText(textsafe.Line(e.SummaryLine()) + "\n")
}

func (summarySink) incomplete(p exchange.Pending) {
	emitText(textsafe.Line(p.SummaryLine()) + "\n")
}

func (summarySink) notice(msg string) {
	emitText("! " + textsafe.Line(msg) + "\n")
}

func (summarySink) start(info runInfo) {
	if len(info.Command) == 0 {
		return // httpmon proxy prints its own banner
	}
	fmt.Fprintf(os.Stderr, "httpmon %s: running %s\n", info.Version, strings.Join(info.Command, " "))
}

func (summarySink) end(d *exchange.Digest) {
	emitText(textsafe.Line(d.String()) + "\n")
}

// ---- JSON ----

// jsonSink writes one object per completed exchange. Everything else in the
// stream -- the start of the run, notices, the end -- is an object too, with
// an "event" field, so every line of the stream parses.
type jsonSink struct{}

type jsonEvent struct {
	Event      string            `json:"event"`
	Message    string            `json:"message,omitempty"`
	Incomplete *exchange.Pending `json:"exchange,omitempty"`
	Run        *runInfo          `json:"run,omitempty"`
	Digest     *exchange.Digest  `json:"digest,omitempty"`
}

func (jsonSink) requestHead(int, *requestFacts)                            {}
func (jsonSink) requestBody(int, *requestFacts, bodyView)                  {}
func (jsonSink) responseHead(int, *responseFacts)                          {}
func (jsonSink) responseBody(int, *responseFacts, bodyView)                {}
func (jsonSink) failed(int, *requestFacts, *exchange.Error, time.Duration) {}
func (jsonSink) wsMessage(int, wsMessage)                                  {}
func (jsonSink) wsClosed(int, wsSummary)                                   {}
func (jsonSink) connect(string)                                            {}

func (jsonSink) exchange(e *exchange.Exchange) { emitJSON(e) }

func (jsonSink) incomplete(p exchange.Pending) {
	emitJSON(jsonEvent{Event: "incomplete", Incomplete: &p})
}

func (jsonSink) notice(msg string) { emitJSON(jsonEvent{Event: "notice", Message: msg}) }

func (jsonSink) start(info runInfo) { emitJSON(jsonEvent{Event: "start", Run: &info}) }

func (jsonSink) end(d *exchange.Digest) { emitJSON(jsonEvent{Event: "end", Digest: d}) }
