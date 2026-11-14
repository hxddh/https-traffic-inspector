package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/hxddh/https-traffic-inspector/v2/internal/body"
	"github.com/hxddh/https-traffic-inspector/v2/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v2/internal/textsafe"
)

// ---- httpmon query ----
//
// A record holds every exchange with its raw bytes, which makes it large: it
// is for replay, not for reading. query is how it is read -- an overview
// first, then any single exchange or body in full, at whatever cost the
// reader chooses.

type queryFilter struct {
	id     int
	status *exchange.FailOn // reuses the --fail-on vocabulary: 5xx, 404, error
	method string
	url    string
	errors bool
}

func (q *queryFilter) match(e *exchange.Exchange) bool {
	switch {
	case q.id != 0 && e.ID != q.id:
		return false
	case q.method != "" && !strings.EqualFold(e.Method, q.method):
		return false
	case q.url != "" && !strings.Contains(strings.ToLower(e.URL), strings.ToLower(q.url)):
		return false
	case q.errors && e.Error == nil:
		return false
	case q.status != nil && !q.status.Match(e):
		return false
	}
	return true
}

func cmdQuery(args []string) int {
	fs := flag.NewFlagSet("httpmon query", flag.ContinueOnError)
	var out outputFlags
	out.register(fs)
	var q queryFilter
	fs.IntVar(&q.id, "id", 0, "only the exchange with this id")
	status := fs.String("status", "", "only exchanges matching these statuses: classes (5xx), codes (404) or error, comma-separated")
	fs.StringVar(&q.method, "method", "", "only this method")
	fs.StringVar(&q.url, "url", "", "only URLs containing this text (case-insensitive)")
	fs.BoolVar(&q.errors, "error", false, "only exchanges that got no response")
	bodyFlag := fs.String("body", "", "print one exchange's decoded body in full: request or response (needs --id)")
	format := fs.String("format", "summary", "output format: summary | json | text")
	maxBody := fs.Int("max-body", 4000, "approximate max bytes of each body shown")
	follow := fs.Bool("follow", false, "keep reading as exchanges are appended to the record")
	show := fs.Bool("show-secrets", false, "show credentials instead of masking them")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon query <record> [filters] [options]

Reads a --record file ("-" for stdin). Without filters it lists every
exchange, one line each; --id N shows one exchange in full, and
--id N --body response prints its decoded body.

Options:
`)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) != 1 {
		fs.Usage()
		return 1
	}
	if *status != "" {
		f, err := exchange.ParseFailOn(*status)
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon query: %s\n", strings.Replace(err.Error(), "--fail-on", "--status", 1))
			return 1
		}
		q.status = f
	}
	if *bodyFlag != "" && *bodyFlag != "request" && *bodyFlag != "response" {
		fmt.Fprintf(os.Stderr, "httpmon query: --body must be request or response\n")
		return 1
	}
	if *bodyFlag != "" && q.id == 0 {
		fmt.Fprintf(os.Stderr, "httpmon query: --body needs --id\n")
		return 1
	}
	switch *format {
	case "summary", "json", "text":
	default:
		fmt.Fprintf(os.Stderr, "httpmon query: unknown --format %q (want summary, json or text)\n", *format)
		return 1
	}
	if *maxBody <= 0 {
		fmt.Fprintf(os.Stderr, "httpmon query: --max-body must be greater than 0\n")
		return 1
	}
	displayMaxBody = *maxBody
	showSecrets = *show

	var in io.Reader = os.Stdin
	if pos[0] != "-" {
		f, err := os.Open(pos[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon query: %v\n", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	w, err := out.open(os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon query: %v\n", err)
		return 1
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)

	var digest exchange.Digest
	matched, bad := 0, 0
	err = readRecords(in, *follow, stop, func(e *exchange.Exchange) bool {
		if !q.match(e) {
			return true
		}
		matched++
		if *bodyFlag != "" {
			bad += writeBody(w, e, *bodyFlag)
			return false
		}
		prepareForDisplay(e)
		digest.Add(e)
		switch *format {
		case "summary":
			emitText(textsafe.Line(e.SummaryLine()) + "\n")
		case "json":
			emitJSON(e)
		case "text":
			emitText(renderExchangeText(e))
		}
		return true
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon query: %v\n", err)
		return 1
	}
	if *bodyFlag != "" {
		if matched == 0 {
			fmt.Fprintf(os.Stderr, "httpmon query: no exchange #%d\n", q.id)
			return 1
		}
		if bad > 0 {
			return 1
		}
		return 0
	}
	if *format == "summary" && !*follow && matched != 1 {
		emitText(textsafe.Line(digest.String()) + "\n")
	}
	if matched == 0 && q.id != 0 {
		fmt.Fprintf(os.Stderr, "httpmon query: no exchange #%d\n", q.id)
		return 1
	}
	return 0
}

// readRecords calls fn for each exchange in r until fn returns false. With
// follow it waits at the end for more to be appended, until stop fires.
// Lines that are not exchanges are reported and skipped.
func readRecords(r io.Reader, follow bool, stop <-chan os.Signal, fn func(*exchange.Exchange) bool) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var pending []byte
	lineNo := 0
	for {
		chunk, err := br.ReadBytes('\n')
		pending = append(pending, chunk...)
		if errors.Is(err, io.EOF) {
			if !follow {
				if len(bytes.TrimSpace(pending)) == 0 {
					return nil
				}
				// A last line without a newline is still a line.
			} else {
				select {
				case <-stop:
					return nil
				case <-time.After(200 * time.Millisecond):
				}
				continue // keep the partial line until its newline arrives
			}
		} else if err != nil {
			return err
		}
		line := bytes.TrimSpace(pending)
		pending = nil
		lineNo++
		if len(line) == 0 {
			continue
		}
		var e exchange.Exchange
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Fprintf(os.Stderr, "httpmon query: line %d: not an exchange record: %v\n", lineNo, err)
			continue
		}
		if e.V != exchange.Version {
			return fmt.Errorf("line %d: record version %d; this httpmon reads only version %d records", lineNo, e.V, exchange.Version)
		}
		if !fn(&e) {
			return nil
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

// prepareForDisplay masks credentials, re-renders bodies from their raw bytes
// within the display budget, and drops the raw bytes, which are for replay.
func prepareForDisplay(e *exchange.Exchange) {
	e.URL = displayURL(e.URL)
	e.Request.Headers = exchange.FromHTTP(displayHeaders(e.Request.Headers.HTTP()))
	e.Request.Body, _ = rerender(e.Request.Headers, e.Request.Body)
	if e.Response != nil {
		e.Response.Headers = exchange.FromHTTP(displayHeaders(e.Response.Headers.HTTP()))
		if len(e.Response.Trailers) > 0 {
			e.Response.Trailers = exchange.FromHTTP(displayHeaders(e.Response.Trailers.HTTP()))
		}
		var hint string
		e.Response.Body, hint = rerender(e.Response.Headers, e.Response.Body)
		if e.Status >= 400 {
			e.Hint = hint
		}
	}
	if e.WebSocket != nil {
		for i := range e.WebSocket.Messages {
			m := &e.WebSocket.Messages[i]
			if m.Text != nil && len(*m.Text) > displayMaxBody {
				s := (*m.Text)[:displayMaxBody]
				m.Text, m.Truncated = &s, true
			}
		}
	}
}

func rerender(h exchange.Headers, b *body.Rendered) (*body.Rendered, string) {
	if b == nil {
		return nil, ""
	}
	if b.Raw == nil {
		hint := ""
		if b.JSON != nil {
			hint = body.ErrorHint(b.JSON)
		}
		return b, hint
	}
	raw, err := b.Raw.Bytes()
	if err != nil {
		b.Raw = nil
		return b, ""
	}
	r, hint := body.Render(h.HTTP(), raw, b.Raw.Truncated, b.Size, displayMaxBody)
	return r, hint
}

// writeBody prints one body, decoded from its Content-Encoding, in full. On a
// terminal it is made safe to display; into a pipe or file the bytes go as
// they are, so they can be processed.
func writeBody(w io.Writer, e *exchange.Exchange, which string) int {
	var b *body.Rendered
	switch {
	case which == "request":
		b = e.Request.Body
	case e.Response != nil:
		b = e.Response.Body
	}
	if b == nil {
		fmt.Fprintf(os.Stderr, "httpmon query: exchange #%d has no %s body\n", e.ID, which)
		return 1
	}
	var data []byte
	truncated := false
	switch {
	case b.Raw != nil:
		raw, err := b.Raw.Bytes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon query: %v\n", err)
			return 1
		}
		data, truncated = decodeContent(b.ContentEncoding, raw, b.Raw.Truncated)
	case b.Text != nil:
		data, truncated = []byte(*b.Text), b.Truncated
	case b.JSON != nil:
		data, _ = json.Marshal(b.JSON)
		truncated = b.Truncated
	default:
		fmt.Fprintf(os.Stderr, "httpmon query: exchange #%d's %s body was not kept (record it with --record)\n", e.ID, which)
		return 1
	}
	if isTerminal(w) {
		data = []byte(textsafe.Terminal(string(data)))
	}
	w.Write(data) //nolint:errcheck
	if truncated {
		fmt.Fprintf(os.Stderr, "httpmon query: only the first %d bytes of this body were recorded\n", len(data))
	}
	return 0
}

// renderExchangeText renders one exchange in the text style, for reading.
func renderExchangeText(e *exchange.Exchange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n", paint(colCyan, fmt.Sprintf("=== #%d %s %s ===", e.ID, textsafe.Line(e.Method), textsafe.Line(e.URL))))
	fmt.Fprintf(&b, "Time: %s  Duration: %.0fms\n", e.Time, e.DurationMs)
	b.WriteString("\nRequest headers:\n")
	writeHeaderBlock(&b, e.Request.Headers)
	writeRenderedBody(&b, "Request body", e.Request.Body)
	switch {
	case e.Error != nil:
		fmt.Fprintf(&b, "\n%s\n", paint(colRed, fmt.Sprintf("FAILED: %s", e.Error.Kind)))
		b.WriteString(textsafe.Terminal(e.Error.Message) + "\n")
	case e.Response != nil:
		fmt.Fprintf(&b, "\n%s\n", paint(colGreen, fmt.Sprintf("Response: %d %s %s", e.Status, textsafe.Line(e.StatusText), e.Response.Proto)))
		writeHeaderBlock(&b, e.Response.Headers)
		writeRenderedBody(&b, "Response body", e.Response.Body)
		if len(e.Response.Trailers) > 0 {
			b.WriteString("\nTrailers:\n")
			writeHeaderBlock(&b, e.Response.Trailers)
		}
		if e.GRPC != nil {
			fmt.Fprintf(&b, "\ngRPC status: %d %s %s\n", e.GRPC.Code, e.GRPC.Name, textsafe.Line(e.GRPC.Message))
		}
	}
	if e.WebSocket != nil {
		fmt.Fprintf(&b, "\nWebSocket messages: %d\n", len(e.WebSocket.Messages)+e.WebSocket.Dropped)
		for _, m := range e.WebSocket.Messages {
			fmt.Fprintf(&b, "%s %s %s (%d bytes)\n", m.Time, m.From, m.Type, m.Size)
			switch {
			case m.Text != nil:
				b.WriteString(quoteBody(*m.Text) + "\n")
			case m.CloseCode != 0:
				b.WriteString(quoteBody(fmt.Sprintf("%d %s", m.CloseCode, m.CloseReason)) + "\n")
			}
		}
	}
	return b.String()
}

func writeRenderedBody(b *strings.Builder, title string, r *body.Rendered) {
	if r == nil {
		return
	}
	var s string
	switch {
	case r.JSON != nil:
		j, _ := json.MarshalIndent(r.JSON, "", "  ")
		s = string(j)
	case r.Text != nil:
		s = *r.Text
	case len(r.GRPC) > 0:
		j, _ := json.MarshalIndent(r.GRPC, "", "  ")
		s = string(j)
	default:
		s = fmt.Sprintf("[binary, %d bytes]", r.Size)
	}
	if r.Truncated {
		s += truncationMarker
	}
	fmt.Fprintf(b, "\n%s:\n%s\n", title, quoteBody(s))
}
