package main

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hxddh/https-traffic-inspector/v3/internal/body"
	"github.com/hxddh/https-traffic-inspector/v3/internal/exchange"
)

// ---- exchange events ----
//
// Each exchange produces, in order: a request head, a request body, a response
// head and a response body -- or, instead of the response, a failure. The two
// bodies are sampled as they stream, so the request body may finish after the
// response has started. Each event goes to the active sink; the completed
// exchange goes to captures for --record and --har.

var (
	requestCounter int
	counterMu      sync.Mutex

	// per-request start times for duration tracking
	reqStartTimes = make(map[int]time.Time)
	reqStartMu    sync.Mutex

	// unfinished holds logged exchanges that have not completed, so the end
	// of the run can name the ones still waiting.
	unfinished   = make(map[int]exchange.Pending)
	unfinishedMu sync.Mutex
)

func trackUnfinished(id int, method, url string) {
	unfinishedMu.Lock()
	unfinished[id] = exchange.Pending{ID: id, Method: method, URL: url}
	unfinishedMu.Unlock()
}

func untrack(id int) {
	unfinishedMu.Lock()
	delete(unfinished, id)
	unfinishedMu.Unlock()
}

// unfinishedExchanges lists, in id order, the exchanges still waiting.
func unfinishedExchanges() []exchange.Pending {
	unfinishedMu.Lock()
	ids := make([]int, 0, len(unfinished))
	for id := range unfinished {
		ids = append(ids, id)
	}
	unfinishedMu.Unlock()
	sort.Ints(ids)
	out := make([]exchange.Pending, 0, len(ids))
	reqStartMu.Lock()
	unfinishedMu.Lock()
	for _, id := range ids {
		p, ok := unfinished[id]
		if !ok {
			continue
		}
		if start, ok := reqStartTimes[id]; ok {
			p.WaitingMs = millis(time.Since(start))
		}
		p.URL = displayURL(p.URL)
		out = append(out, p)
	}
	unfinishedMu.Unlock()
	reqStartMu.Unlock()
	return out
}

func nextReqID() int {
	counterMu.Lock()
	defer counterMu.Unlock()
	requestCounter++
	return requestCounter
}

// requestFacts carries the request details needed once its body has been
// sampled, since the request itself is forwarded in the meantime.
type requestFacts struct {
	method    string
	rawURL    string // as the client addressed it, without a default port
	proto     string
	host      string
	path      string
	rawQuery  string
	headers   http.Header
	startTime time.Time
}

// responseFacts carries the response details needed once its body has been
// sampled, since the response is forwarded in the meantime.
type responseFacts struct {
	status        int
	statusText    string
	proto         string
	headers       http.Header
	trailers      http.Header
	contentLength int64
	duration      time.Duration
	// upgraded marks a 101 response: the connection now carries WebSocket
	// messages, and the exchange ends when it closes.
	upgraded bool

	// duration is the time to the response head; total, once the body has
	// ended, the time to its last byte.
	start time.Time
	total time.Duration
}

// totalDuration is the whole exchange's duration, as far as it is known.
func (f responseFacts) totalDuration() time.Duration {
	if f.total > 0 {
		return f.total
	}
	return f.duration
}

// bodyView is a captured body. Text is the human-readable form -- decoded
// from its Content-Encoding, or a placeholder for binary data -- and carries no
// truncation marker, which is added only when rendering for display. Raw holds
// the bytes exactly as they crossed the wire, which --record and --har need to
// reproduce the body faithfully.
type bodyView struct {
	Text      string
	Truncated bool // Text is only a prefix of the body

	Raw          []byte
	RawTruncated bool  // Raw is only a prefix of the body
	Size         int64 // bytes seen on the wire
}

// logRequestFacts reports a request and returns its ID, with the facts a
// later failure report needs. The body is sampled as it is forwarded; its
// event follows when it ends.
func logRequestFacts(req *http.Request) (int, *requestFacts) {
	reqID := nextReqID()

	startTime := time.Now()
	reqStartMu.Lock()
	reqStartTimes[reqID] = startTime
	reqStartMu.Unlock()

	// Capture what the body sample will need later; req is reused downstream.
	f := &requestFacts{
		method:    req.Method,
		rawURL:    requestDisplayURL(req),
		proto:     req.Proto,
		host:      req.Host,
		path:      req.URL.Path,
		rawQuery:  req.URL.RawQuery,
		headers:   req.Header.Clone(),
		startTime: startTime,
	}
	trackUnfinished(reqID, f.method, f.rawURL)
	currentSink().requestHead(reqID, f)

	// Sample the body alongside delivery instead of reading a prefix up front.
	// Reading first would hold a chunked upload until the client finished it.
	sampleRequestBody(&req.Body, f.headers, req.ContentLength, func(v bodyView) {
		onRequestBody(reqID, f, v)
	})
	return reqID, f
}

// requestDisplayURL is the URL as the client addressed it: the host from Host
// (or :authority), not the CONNECT target, and no default port.
func requestDisplayURL(req *http.Request) string {
	u := *req.URL
	host := req.Host
	if host == "" {
		host = u.Host
	}
	u.Host = stripDefaultPort(host, u.Scheme)
	return u.String()
}

// stripDefaultPort removes :443 from an https host and :80 from an http one.
func stripDefaultPort(host, scheme string) string {
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// onRequestBody runs when a request body finishes streaming.
func onRequestBody(reqID int, f *requestFacts, v bodyView) {
	captures.addRequest(reqID, capturedRequest{facts: *f, body: v})
	currentSink().requestBody(reqID, f, v)
}

func requestDuration(reqID int) time.Duration {
	reqStartMu.Lock()
	start := reqStartTimes[reqID]
	delete(reqStartTimes, reqID)
	reqStartMu.Unlock()
	if start.IsZero() {
		return 0
	}
	return time.Since(start)
}

// logResponse reports a response head and samples its body as it is relayed.
func logResponse(resp *http.Response, reqID int) {
	f := &responseFacts{
		status:        resp.StatusCode,
		statusText:    resp.Status,
		proto:         resp.Proto,
		headers:       resp.Header.Clone(),
		contentLength: resp.ContentLength,
		duration:      requestDuration(reqID),
		upgraded:      resp.StatusCode == http.StatusSwitchingProtocols,
	}
	f.start = time.Now().Add(-f.duration)
	currentSink().responseHead(reqID, f)

	// Sample alongside delivery. Reading a prefix first would withhold an SSE
	// feed or any slow response until the upstream closed the stream.
	//
	// Trailers are read when the body completes: the transport fills
	// resp.Trailer in place just before the body reports EOF.
	sampleResponseBody(&resp.Body, f.headers, f.contentLength, f.status, func(v bodyView) {
		f.trailers = resp.Trailer.Clone()
		f.total = time.Since(f.start)
		onResponseBody(reqID, f, v)
	})
}

// onResponseBody runs when a response body finishes streaming.
func onResponseBody(reqID int, f *responseFacts, v bodyView) {
	if !f.upgraded {
		captures.addResponse(reqID, capturedResponse{facts: *f, body: v})
	}
	currentSink().responseBody(reqID, f, v)
}

// logFailure reports an exchange that will get no response.
func logFailure(reqID int, f *requestFacts, err error) {
	dur := requestDuration(reqID)
	info := exchange.Describe(err, f.rawURL)
	captures.addFailure(reqID, info, dur)
	currentSink().failed(reqID, f, info, dur)
}

// truncationMarker is appended whenever displayed content is incomplete, so a
// cut-off body is never mistaken for the whole thing.
const truncationMarker = "\n… [truncated]"

// truncateForDisplay caps v at displayMaxBody bytes, backing off to a rune
// boundary so multi-byte characters are never split. Content cut here, or
// already cut at capture time, is marked so it is never read as complete.
func truncateForDisplay(v bodyView) string {
	s := v.Text
	if len(s) > displayMaxBody {
		cut := displayMaxBody
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut] + truncationMarker
	}
	if v.Truncated {
		return s + truncationMarker
	}
	return s
}

// isPrintableContentType returns true when the MIME type suggests human-readable text.
func isPrintableContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if ct == "" {
		return true
	}
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "html") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "form")
}

// isPrintable returns true when the Content-Type suggests human-readable text
// AND the Content-Encoding is not a compression scheme.
func isPrintable(header http.Header) bool {
	if len(body.SplitEncodings(header.Get("Content-Encoding"))) > 0 {
		return false
	}
	return isPrintableContentType(header.Get("Content-Type"))
}

// flattenHeaders joins each header's values for a JSON object.
func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}
