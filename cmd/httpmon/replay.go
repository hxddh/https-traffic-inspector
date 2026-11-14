package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/session"
	"github.com/hxddh/https-traffic-inspector/v4/internal/textsafe"
)

// replayResult is the outcome of replaying a single recorded exchange.
type replayResult struct {
	ID             int    `json:"id"`
	Session        string `json:"session,omitempty"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	RecordedStatus int    `json:"recorded_status"`
	ActualStatus   int    `json:"actual_status"`
	StatusMatch    bool   `json:"status_match"`
	BodyMatch      bool   `json:"body_match"`
	DurationMs     int64  `json:"duration_ms"`
	Err            string `json:"error,omitempty"`
	// Skipped explains why the exchange was not re-sent.
	Skipped string `json:"skipped,omitempty"`
	// gRPC calls report their status from the trailers as well.
	RecordedGRPCStatus string `json:"recorded_grpc_status,omitempty"`
	ActualGRPCStatus   string `json:"actual_grpc_status,omitempty"`
}

// Differs reports whether the replayed response deviated from the recording.
func (r replayResult) Differs() bool {
	if r.Skipped != "" {
		return false
	}
	return r.Err != "" || !r.StatusMatch || !r.BodyMatch
}

// Reasons an exchange is not re-sent. Each is a request httpmon cannot
// reproduce faithfully; sending an approximation would make the server see a
// different request and report a difference that is not real.
const (
	websocketReplaySkip = "WebSocket connection"
	failedReplaySkip    = "the recorded exchange got no response"
	truncatedReqSkip    = "request body was only partly recorded"
	noRawSkip           = "the record has no raw bytes for the request body (made with --format json, not a session?)"
	redactedReplaySkip  = "credentials were masked by --redact"
)

// replayFile reads a record and replays each exchange. If targetBase is
// non-empty it replaces the scheme and host of every URL. Results go to
// httpmon's output.
//
// Exit codes: 0 = clean, 1 = read/parse failure, 2 = differences found while
// failOnDiff is set (so CI can gate on it).
func replayFile(arg, targetBase string, delayBetween time.Duration, failOnDiff bool) int {
	path, err := session.Resolve(arg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon replay: %v\n", err)
		return 1
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon replay: %v\n", err)
		return 1
	}
	defer f.Close()

	// The proxy's own client, so replay follows the same verification policy
	// and upstream proxy: a recording from a self-signed host, or one taken
	// behind an egress proxy, must still be replayable.
	client := newUpstreamClient(insecureUpstream)

	rd := exchange.NewReader(f)
	n, errs, diffs, skipped := 0, 0, 0, 0
	for {
		e, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon replay: %v\n", err)
			errs++
			if strings.Contains(err.Error(), "record version") {
				break // a whole file of another version; one message is enough
			}
			continue
		}
		if n > 0 && delayBetween > 0 {
			time.Sleep(delayBetween)
		}
		res := replayExchange(client, e, targetBase)
		if res.Differs() {
			diffs++
		}
		if res.Skipped != "" {
			skipped++
		}
		n++
	}
	if !jsonMode {
		emitText(fmt.Sprintf("\n%s replayed %d request(s), %d error(s), %d diff(s), %d skipped\n",
			strings.Repeat("─", 60), n-skipped, errs, diffs, skipped))
	}
	if errs > 0 {
		return 1
	}
	if failOnDiff && diffs > 0 {
		return 2
	}
	return 0
}

// rebase replaces scheme and host in u with targetBase, keeping path, query
// and fragment.
func rebase(u, targetBase string) string {
	if targetBase == "" {
		return u
	}
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
		// Find the first '/' or '?' to split off the host.
		cut := strings.IndexAny(rest, "/?#")
		if cut >= 0 {
			rest = rest[cut:]
		} else {
			rest = "/"
		}
	}
	return strings.TrimRight(targetBase, "/") + rest
}

// replayExchange re-sends one recorded exchange byte for byte and compares
// the response after removing its Content-Encoding.
func replayExchange(client *http.Client, e *exchange.Exchange, targetBase string) replayResult {
	res := replayResult{ID: e.ID, Session: e.Session, Method: e.Method, RecordedStatus: e.Status}
	replayURL := rebase(e.URL, targetBase)
	res.URL = replayURL
	if !jsonMode {
		var b strings.Builder
		fmt.Fprintf(&b, "\n%s\n", paint(colCyan, fmt.Sprintf("── REPLAY #%d (session %s) ──", e.ID, textsafe.Line(e.Session))))
		fmt.Fprintf(&b, "Original:  %s %s  →  %d %s\n", textsafe.Line(e.Method), textsafe.Line(e.URL), e.Status, textsafe.Line(e.StatusText))
		fmt.Fprintf(&b, "Replaying: %s %s\n", textsafe.Line(e.Method), textsafe.Line(replayURL))
		emitText(b.String())
	}

	reqHeader := e.Request.Headers.HTTP()
	rb := e.Request.Body
	switch {
	case e.Kind == "websocket":
		res.Skipped = websocketReplaySkip
	case e.Error != nil:
		res.Skipped = failedReplaySkip
	case rb != nil && rb.Size > 0 && rb.Raw == nil:
		res.Skipped = noRawSkip
	case rb != nil && rb.Raw != nil && rb.Raw.Truncated:
		res.Skipped = truncatedReqSkip
	case e.Redacted && (hasSensitiveHeader(reqHeader) || strings.Contains(e.URL, "…")):
		res.Skipped = redactedReplaySkip
	}
	if res.Skipped != "" {
		emitReplayResult(res, "")
		return res
	}

	var reqBody []byte
	if rb != nil && rb.Raw != nil {
		b, err := rb.Raw.Bytes()
		if err != nil {
			res.Err = "request body: " + err.Error()
			emitReplayResult(res, "")
			return res
		}
		reqBody = b
	}

	grpc := body.IsGRPC(reqHeader.Get("Content-Type"))
	c := client
	if grpc && strings.HasPrefix(replayURL, "http://") {
		// A cleartext gRPC server speaks only HTTP/2.
		c = h2cClient
	}
	resp, dur, err := sendReplay(c, e.Method, replayURL, reqHeader, reqBody)
	res.DurationMs = dur.Milliseconds()
	if err != nil {
		res.Err = err.Error()
		emitReplayResult(res, "")
		return res
	}
	defer resp.Body.Close()
	raw, overflow := readCapped(resp.Body)

	res.ActualStatus = resp.StatusCode
	res.StatusMatch = resp.StatusCode == e.Status
	if grpc && e.Response != nil {
		res.RecordedGRPCStatus = body.GRPCStatus(e.Response.Headers.HTTP(), e.Response.Trailers.HTTP())
		res.ActualGRPCStatus = body.GRPCStatus(resp.Header, resp.Trailer)
		res.StatusMatch = res.StatusMatch && res.RecordedGRPCStatus == res.ActualGRPCStatus
	}

	var recorded []byte
	recTruncated := false
	if e.Response != nil && e.Response.Body != nil && e.Response.Body.Raw != nil {
		rr, err := e.Response.Body.Raw.Bytes()
		if err != nil {
			res.Err = "recorded response body: " + err.Error()
			emitReplayResult(res, "")
			return res
		}
		recorded, recTruncated = decodeContent(e.Response.Body.ContentEncoding, rr, e.Response.Body.Raw.Truncated)
	}
	actual, _ := decodeContent(resp.Header.Get("Content-Encoding"), raw, overflow)
	if recTruncated {
		res.BodyMatch = bytes.HasPrefix(actual, recorded)
	} else {
		res.BodyMatch = bytes.Equal(bytes.TrimSpace(recorded), bytes.TrimSpace(actual))
	}

	emitReplayResult(res, decodeBody(resp.Header, raw, overflow).Text)
	return res
}

func hasSensitiveHeader(h http.Header) bool {
	for k := range h {
		if textsafe.IsSensitiveHeader(k) {
			return true
		}
	}
	return false
}

// sendReplay sends one replayed request. Hop-by-hop headers and framing are
// left to the transport, as they would be for any new request.
func sendReplay(client *http.Client, method, u string, h http.Header, reqBody []byte) (*http.Response, time.Duration, error) {
	var r io.Reader
	if len(reqBody) > 0 {
		r = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return nil, 0, err
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	removeHopByHopHeaders(req.Header)
	req.Header.Del("Content-Length")
	// The target's own host applies, not the one recorded.
	req.Header.Del("Host")

	start := time.Now()
	resp, err := client.Do(req)
	return resp, time.Since(start), err
}

// readCapped reads up to captureMaxBody bytes and reports whether more followed.
func readCapped(r io.Reader) ([]byte, bool) {
	b, _ := io.ReadAll(io.LimitReader(r, int64(captureMaxBody)+1))
	if len(b) > captureMaxBody {
		return b[:captureMaxBody], true
	}
	return b, false
}

// decodeContent removes a Content-Encoding from raw. A body that cannot be
// decoded is returned as it is.
func decodeContent(encoding string, raw []byte, truncated bool) ([]byte, bool) {
	if len(body.SplitEncodings(encoding)) == 0 {
		return raw, truncated
	}
	res, err := body.Decompress(encoding, raw)
	if err != nil {
		return raw, truncated
	}
	return res.Data, truncated || res.Truncated
}

// emitReplayResult renders one replay outcome, as coloured text or NDJSON.
func emitReplayResult(res replayResult, newBody string) {
	if jsonMode {
		emitJSON(res)
		return
	}

	var b strings.Builder
	switch {
	case res.Skipped != "":
		fmt.Fprintf(&b, "  %s: %s\n", paint(colYellow, "SKIP"), res.Skipped)
	case res.Err != "":
		fmt.Fprintf(&b, "  %s: %s\n", paint(colRed, "FAIL"), textsafe.Line(res.Err))
	default:
		statusIcon := paint(colGreen, "✓")
		if !res.StatusMatch {
			statusIcon = paint(colRed, "✗")
		}
		fmt.Fprintf(&b, "  Status:  %s  recorded=%d  actual=%d  (%dms)\n",
			statusIcon, res.RecordedStatus, res.ActualStatus, res.DurationMs)
		if res.RecordedGRPCStatus != "" || res.ActualGRPCStatus != "" {
			fmt.Fprintf(&b, "  gRPC:    recorded=%s  actual=%s\n", res.RecordedGRPCStatus, res.ActualGRPCStatus)
		}
		if res.BodyMatch {
			fmt.Fprintf(&b, "  Body:    %s\n", paint(colGreen, "✓ unchanged"))
		} else {
			fmt.Fprintf(&b, "  Body:    %s\n", paint(colYellow, "≠ changed"))
			r := []rune(newBody)
			if len(r) > 200 {
				newBody = string(r[:200]) + "…"
			}
			fmt.Fprintf(&b, "    now: %s\n", textsafe.Line(newBody))
		}
	}
	emitText(b.String())
}
