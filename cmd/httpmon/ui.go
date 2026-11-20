package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hxddh/https-traffic-inspector/v5/internal/body"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v5/internal/session"
	"github.com/hxddh/https-traffic-inspector/v5/internal/store"
	"github.com/hxddh/https-traffic-inspector/v5/internal/textsafe"
)

// ---- httpmon ui ----
//
// The interactive UI over a session: what a running "httpmon proxy" captures,
// as it happens, or what an earlier run recorded.

var (
	tuiTitle    string // replaces the proxy address in the header
	tuiReadOnly bool   // no replay
)

func cmdUI(args []string) int {
	fs := flag.NewFlagSet("httpmon ui", flag.ContinueOnError)
	last := fs.Int("last", 1000, "show this many of the session's most recent exchanges")
	readOnly := fs.Bool("read-only", false, "do not offer replay")
	show := fs.Bool("show-secrets", false, "show credentials instead of masking them")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon ui <session> [options]

Opens the interactive UI on a session. A running session -- "httpmon proxy",
or a command run with --session -- is followed as it grows; an ended one is
shown as recorded. Keys: [/] search (a method, URL, status, error, or
[mock], [fault], [map]), [enter] detail, [c] copy as curl, [e] export,
[r] replay the request, [q] quit.

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
	if !isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "httpmon ui: needs a terminal; use httpmon query to read a session in a script")
		return 1
	}
	if *last <= 0 {
		*last = maxTUIEntries
	}
	showSecrets, tuiReadOnly = *show, *readOnly
	st, err := openStore(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon ui: %v\n", err)
		return 1
	}
	defer st.Close()

	running := false
	var m session.Meta
	if st.Dir != "" && session.ReadJSON(st.Dir, session.MetaFile, &m) == nil {
		running = m.RunningIn(st.Dir)
	}
	name := pos[0]
	if st.Dir != "" {
		name = filepath.Base(st.Dir)
	}
	tuiTitle = "httpmon  session " + textsafe.Line(name)
	if running {
		tuiTitle += "  (live)"
	}

	entries := st.Entries
	if len(entries) > min(*last, maxTUIEntries) {
		entries = entries[len(entries)-min(*last, maxTUIEntries):]
	}
	for _, en := range entries {
		e, err := st.Read(en)
		if err != nil {
			tuiSend(tuiNoticeMsg{err.Error()})
			break
		}
		tuiSend(tuiReqMsg{tuiEntryFrom(e)})
	}
	if st.Dir != "" && m.Dropped > 0 {
		tuiSend(tuiNoticeMsg{fmt.Sprintf("the session's oldest exchanges were dropped to keep it under its size limit (%d segments)", m.Dropped)})
	}

	stop := make(chan os.Signal, 1)
	if running {
		path, end := st.Tail()
		go followFrom(st.Dir, path, end, stop, nil, func(e *exchange.Exchange) bool { //nolint:errcheck
			tuiSend(tuiReqMsg{tuiEntryFrom(e)})
			return true
		})
		go watchInFlight(st.Dir, stop)
	}
	runTUI()
	close(stop)
	return 0
}

// watchInFlight shows a running session's in-flight count on the status bar.
func watchInFlight(dir string, stop <-chan os.Signal) {
	last := -1
	for {
		select {
		case <-stop:
			return
		case <-time.After(time.Second):
		}
		var l session.Live
		if session.ReadJSON(dir, session.LiveFile, &l) != nil {
			continue
		}
		if n := len(l.InFlight); n != last {
			last = n
			tuiSend(tuiFlashMsg{fmt.Sprintf("%d in flight", n)})
		}
	}
}

// tuiEntryFrom turns a recorded exchange into a UI entry, masked for display.
func tuiEntryFrom(e *exchange.Exchange) *tuiEntry {
	start, _ := time.Parse(time.RFC3339Nano, e.Time)
	if e.Status >= 400 && e.Response != nil {
		e.Hint = store.HintOf(e.Response)
	}
	en := &tuiEntry{
		id: e.ID, startTime: start, method: e.Method, rule: e.Rule,
		curlURL: e.URL, rawReqHeaders: e.Request.Headers.HTTP(),
		duration: time.Duration(e.DurationMs * float64(time.Millisecond)),
	}
	if e.Redacted {
		// Its credentials are masked: replay would send the masks.
		en.rawReqHeaders = nil
	}
	if b := e.Request.Body; b != nil && b.Raw != nil {
		if raw, err := b.Raw.Bytes(); err == nil {
			en.reqBodyRaw, en.reqBodyWhole = raw, !b.Raw.Truncated
		}
	}
	prepareForDisplay(e)
	en.extraMeta = strings.TrimSpace(formatExchangeXRay(e))
	en.rawURL = e.URL
	// The list shows host and path: take them from the masked URL, so a
	// token in the query is not shown. The real URL stays in curlURL.
	if u, err := url.Parse(e.URL); err == nil && u.Host != "" {
		en.host, en.path = u.Host, u.RequestURI()
	} else {
		en.host = e.URL
	}
	en.reqHeaders = flattenHeaders(e.Request.Headers.HTTP())
	en.reqBody = renderedText(e.Request.Body)
	switch {
	case e.Kind == "tunnel" && e.Tunnel != nil:
		en.status = 200
		en.statusText = fmt.Sprintf("TUNNEL (%d B↑ %d B↓)", e.Tunnel.BytesUp, e.Tunnel.BytesDown)
	case e.Error != nil:
		en.failed = e.Error.Kind + ": " + e.Error.Message
	case e.Response != nil:
		en.status = e.Status
		en.statusText = fmt.Sprintf("%d %s", e.Status, e.StatusText)
		en.respHeaders = flattenHeaders(e.Response.Headers.HTTP())
		en.respBody = renderedText(e.Response.Body)
		if len(e.Response.Trailers) > 0 {
			en.respTrailer = flattenHeaders(e.Response.Trailers.HTTP())
		}
		if g := e.GRPC; g != nil {
			en.grpcLine = fmt.Sprintf("gRPC status: %d %s %s", g.Code, g.Name, g.Message)
		}
	}
	if ws := e.WebSocket; ws != nil {
		en.ws, en.wsCount = true, len(ws.Messages)+ws.Dropped
		en.wsClosed = "recorded"
		for _, m := range ws.Messages {
			line := fmt.Sprintf("%s %s %s (%d bytes)", m.Time, m.From, m.Type, m.Size)
			if m.Text != nil {
				line += "\n  " + strings.ReplaceAll(*m.Text, "\n", "\n  ")
			}
			en.wsLines = append(en.wsLines, line)
		}
		if len(en.wsLines) > maxWSLines {
			en.wsLines = en.wsLines[len(en.wsLines)-maxWSLines:]
		}
	}
	return en
}

// renderedText is a rendered body as the UI shows it.
func renderedText(r *body.Rendered) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	writeRenderedBody(&b, "", r)
	s := strings.TrimPrefix(b.String(), "\n:\n")
	return strings.TrimSuffix(s, "\n")
}

// ruleTags is "[mock] [fault]" for the rules in a label.
func ruleTags(label string) string {
	if label == "" {
		return ""
	}
	var tags []string
	for _, part := range strings.Split(label, "; ") {
		kind, _, _ := strings.Cut(part, ":")
		tags = append(tags, "["+kind+"]")
	}
	return strings.Join(tags, " ")
}

// replaySelected sends the selected request again, straight to its server,
// and reports the outcome on the status bar.
func (m *tuiModel) replaySelected() {
	e := m.selected()
	switch {
	case e == nil:
		return
	case tuiReadOnly:
		m.flash = "replay is off (--read-only)"
		return
	case e.ws:
		m.flash = "a WebSocket connection cannot be replayed"
		return
	case e.rawReqHeaders == nil:
		m.flash = "this exchange's credentials were redacted; it cannot be replayed"
		return
	case len(e.reqBodyRaw) > 0 && !e.reqBodyWhole:
		m.flash = "only part of the request body was captured; it cannot be replayed"
		return
	}
	m.flash = fmt.Sprintf("replaying #%d…", e.id)
	method, target, headers, reqBody, id := e.method, e.curlURL, e.rawReqHeaders.Clone(), e.reqBodyRaw, e.id
	go func() {
		tuiSend(tuiFlashMsg{replayOnce(id, method, target, headers, reqBody)})
	}()
}

// replayOnce sends one request and describes the outcome.
func replayOnce(id int, method, target string, headers http.Header, reqBody []byte) string {
	c := newUpstreamClient(insecureUpstream)
	if body.IsGRPC(headers.Get("Content-Type")) && strings.HasPrefix(target, "http://") {
		c = h2cClient
	}
	resp, dur, err := sendReplay(c, method, target, headers, reqBody)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Sprintf("replay #%d: ERR %v", id, err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return fmt.Sprintf("replay #%d → %d (%s, %d B)", id, resp.StatusCode, dur.Round(time.Millisecond), n)
}
