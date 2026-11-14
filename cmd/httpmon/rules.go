package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/rules"
	"github.com/hxddh/https-traffic-inspector/v4/internal/textsafe"
)

// ruleLabels maps an exchange ID to the rules that touched it, for its record.
var ruleLabels sync.Map // int -> string

func setRuleLabel(id int, label string) {
	if prev, ok := ruleLabels.Load(id); ok {
		label = prev.(string) + "; " + label
	}
	ruleLabels.Store(id, label)
	if tuiMode {
		tuiSend(tuiRuleMsg{reqID: id, rule: label})
	}
}

func ruleLabel(id int) string {
	if v, ok := ruleLabels.Load(id); ok {
		return v.(string)
	}
	return ""
}

// maxInjectedTimeout bounds a "timeout" fault: the request is held until the
// client gives up, or this long.
const maxInjectedTimeout = 10 * time.Minute

// ruleOutcome is what applyRules decided.
type ruleOutcome struct {
	done  bool  // the request has been answered (or failed); stop
	mapTo *url2 // send the request here instead
	reset int64 // reset the connection after this many response body bytes (>0)
	// headers are the header rules to apply, request and response.
	headers []*rules.Rule
}

// url2 is a scheme and host to send a mapped request to.
type url2 struct{ scheme, host string }

// applyRules runs the --fault, --mock, --mock-from and --map rules for a
// request, before it is forwarded. host is the request's host as the client
// addressed it, without a default port.
func applyRules(w http.ResponseWriter, req *http.Request, host string, reqID int, facts *requestFacts) ruleOutcome {
	var out ruleOutcome
	if activeRules.Empty() && recordedMocks == nil {
		return out
	}
	d := activeRules.Decide(req.Method, host, req.URL.Path, req.Header)
	label := func(s string) {
		if facts != nil {
			setRuleLabel(reqID, s)
		}
	}

	for _, h := range d.Headers {
		label(h.Label())
	}
	out.headers = d.Headers
	if f := d.Fault; f != nil {
		label(f.Label())
		switch f.Action {
		case rules.FaultDelay:
			t := time.NewTimer(f.Delay)
			select {
			case <-t.C:
			case <-req.Context().Done():
				t.Stop()
			}
		case rules.FaultReset:
			if f.After > 0 {
				out.reset = f.After
				break
			}
			failInjected(req, reqID, facts, f.Label(), false)
		case rules.FaultTimeout:
			failInjected(req, reqID, facts, f.Label(), true)
		}
	}

	if m := d.Mock; m != nil {
		label(m.Label())
		h := http.Header{}
		if m.ContentType != "" {
			h.Set("Content-Type", m.ContentType)
		}
		serveSynthetic(w, req, reqID, facts, m.Status, h, m.Body)
		out.done = true
		return out
	}
	if rec := recordedMocks.Lookup(req.Method, host, req.URL.Path, req.URL.RawQuery); rec != nil {
		label("mock-from: #" + strconv.Itoa(rec.ID))
		status, h, b := recordedResponse(rec)
		serveSynthetic(w, req, reqID, facts, status, h, b)
		out.done = true
		return out
	}
	if m := d.Map; m != nil {
		label(m.Label())
		out.mapTo = &url2{scheme: m.To.Scheme, host: m.To.Host}
	}
	return out
}

// failInjected fails a request on purpose: at once (reset), or once the
// client gives up waiting (timeout). It does not return: the handler is
// aborted, which drops the connection (HTTP/1) or resets the stream (HTTP/2).
func failInjected(req *http.Request, reqID int, facts *requestFacts, label string, wait bool) {
	// Read the request first: its body completes the request half of the
	// exchange, and a client still sending would see a different failure.
	if req.Body != nil {
		io.Copy(io.Discard, req.Body) //nolint:errcheck
	}
	if wait {
		ctx, cancel := context.WithTimeout(req.Context(), maxInjectedTimeout)
		<-ctx.Done()
		cancel()
	}
	if facts != nil {
		logFailure(reqID, facts, &exchange.InjectedError{Rule: label})
	}
	panic(http.ErrAbortHandler)
}

// serveSynthetic answers a request with a response httpmon made up, logged
// and recorded like a forwarded one.
func serveSynthetic(w http.ResponseWriter, req *http.Request, reqID int, facts *requestFacts, status int, h http.Header, b []byte) {
	if req.Body != nil {
		io.Copy(io.Discard, req.Body) //nolint:errcheck
		req.Body.Close()              //nolint:errcheck
	}
	if !bodyAllowedForStatus(status) {
		b = nil
	}
	h.Set("Content-Length", strconv.Itoa(len(b)))
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(b)),
		ContentLength: int64(len(b)),
	}
	if facts != nil {
		logResponse(resp, reqID)
	}
	defer func() { resp.Body.Close() }() //nolint:errcheck
	for k, v := range h {
		w.Header()[k] = v
	}
	w.WriteHeader(status)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// recordedResponse is a recorded exchange's response, ready to send again.
func recordedResponse(e *exchange.Exchange) (int, http.Header, []byte) {
	h := e.Response.Headers.HTTP()
	removeHopByHopHeaders(h)
	h.Del("Content-Length")
	var b []byte
	if rb := e.Response.Body; rb != nil && rb.Raw != nil {
		b, _ = rb.Raw.Bytes()
	}
	return e.Status, h, b
}

// ---- httpmon mock ----

func cmdMock(args []string) int {
	fs := flag.NewFlagSet("httpmon mock", flag.ContinueOnError)
	port := fs.String("port", "8080", "port to listen on; 0 picks a free port")
	listen := fs.String("listen", "127.0.0.1", "address to listen on")
	matchHost := fs.Bool("match-host", false, "match requests on host as well as path (for clients that send a recorded Host)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon mock <session> [options]

Serves a session's recorded responses as an offline mock server. A request
gets the response recorded for the same method, path and query parameter
names; several recorded for one endpoint are served in turn. Point the
client's base URL at the address printed on start.

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
	files, err := sessionFiles(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon mock: %v\n", err)
		return 1
	}
	rec, err := rules.LoadRecordedFiles(files, !*matchHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon mock: %v\n", err)
		return 1
	}
	if rec.Len() == 0 {
		fmt.Fprintf(os.Stderr, "httpmon mock: %s has no recorded responses\n", pos[0])
		return 1
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(*listen, *port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon mock: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "httpmon mock: serving %d recorded responses from %s on http://%s\n", rec.Len(), pos[0], ln.Addr())
	srv := &http.Server{
		Handler:           mockHandler(rec),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go srv.Serve(ln) //nolint:errcheck
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx) //nolint:errcheck
	return 0
}

func mockHandler(rec *rules.Recorded) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		e := rec.Lookup(r.Method, r.Host, r.URL.Path, r.URL.RawQuery)
		if e == nil {
			fmt.Fprintf(os.Stderr, "%s %s → 404 not recorded\n", r.Method, textsafe.Line(r.URL.RequestURI()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"error":    "httpmon mock: no recorded response for " + r.Method + " " + r.URL.Path,
				"recorded": rec.Endpoints(),
			})
			return
		}
		status, h, b := recordedResponse(e)
		fmt.Fprintf(os.Stderr, "%s %s → %d (recorded #%d)\n", r.Method, textsafe.Line(r.URL.RequestURI()), status, e.ID)
		for k, v := range h {
			w.Header()[k] = v
		}
		if bodyAllowedForStatus(status) {
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		} else {
			b = nil
		}
		w.WriteHeader(status)
		w.Write(b) //nolint:errcheck,gosec // G705: replays a recorded response, as asked
	})
}

// applyHeaderRules makes the header rules' changes in one direction.
func applyHeaderRules(rs []*rules.Rule, dir string, h http.Header) {
	for _, r := range rs {
		if r.Dir == dir {
			r.Apply(h)
		}
	}
}
