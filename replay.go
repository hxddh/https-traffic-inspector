package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// recordedExchange is one request/response pair in the v1 record format,
// written by httpmon 1.x. Replay still reads it.
type recordedExchange struct {
	ID          int               `json:"id"`
	Time        string            `json:"time"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	ReqHeaders  map[string]string `json:"req_headers"`
	ReqBody     string            `json:"req_body,omitempty"`
	Status      int               `json:"status"`
	StatusText  string            `json:"status_text"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody    string            `json:"resp_body,omitempty"`
	// RespTrailers holds trailers sent after the body, where gRPC puts its status.
	RespTrailers map[string]string `json:"resp_trailers,omitempty"`
	DurationMs   int64             `json:"duration_ms"`

	// Set when the stored body is only a prefix: it exceeded --max-capture,
	// or the stream was cut off before it ended.
	ReqBodyTruncated  bool `json:"req_body_truncated,omitempty"`
	RespBodyTruncated bool `json:"resp_body_truncated,omitempty"`
}

// replayResult is the outcome of replaying a single recorded exchange.
type replayResult struct {
	ID             int    `json:"id"`
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
	grpcReplaySkip      = "gRPC call: the v1 recording holds a summary of its binary body, not the bytes"
	placeholderSkip     = "request body is binary: the v1 recording holds a placeholder, not the bytes"
	truncatedReqSkip    = "request body was only partly recorded"
	encodedReqSkip      = "request body was compressed: the v1 recording holds the decoded text"
	websocketReplaySkip = "WebSocket connection"
	failedReplaySkip    = "the recorded exchange got no response"
	redactedReplaySkip  = "credentials were masked by --redact"
)

// replayFile reads an NDJSON recording and replays each exchange.
// If targetBase is non-empty it is used as the URL prefix (scheme+host),
// replacing the original host. Results go to httpmon's output.
//
// Exit codes: 0 = clean, 1 = read/parse failure, 2 = differences found while
// failOnDiff is set (so CI can gate on it).
func replayFile(path, targetBase string, delayBetween time.Duration, failOnDiff bool) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: cannot open %s: %v\n", path, err)
		return 1
	}
	defer f.Close()

	// The proxy's own client, so replay follows the same verification policy
	// and upstream proxy: a recording from a self-signed host, or one taken
	// behind an egress proxy, must still be replayable.
	client := newUpstreamClient(insecureUpstream)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 256*1024*1024)

	n, errs, diffs, skipped := 0, 0, 0, 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var probe struct {
			V int `json:"v"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			fmt.Fprintf(os.Stderr, "replay: malformed line: %v\n", err)
			errs++
			continue
		}

		var res replayResult
		if probe.V >= 2 {
			var ex recordV2
			if err := json.Unmarshal(line, &ex); err != nil {
				fmt.Fprintf(os.Stderr, "replay: malformed line: %v\n", err)
				errs++
				continue
			}
			if n > 0 && delayBetween > 0 {
				time.Sleep(delayBetween)
			}
			res = replayV2(client, &ex, targetBase)
		} else {
			var ex recordedExchange
			if err := json.Unmarshal(line, &ex); err != nil {
				fmt.Fprintf(os.Stderr, "replay: malformed line: %v\n", err)
				errs++
				continue
			}
			if n > 0 && delayBetween > 0 {
				time.Sleep(delayBetween)
			}
			res = replayOne(client, &ex, targetBase)
		}
		if res.Differs() {
			diffs++
		}
		if res.Skipped != "" {
			skipped++
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "replay: read error: %v\n", err)
		return 1
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

func replayHeading(id, seq int, session, method, origURL, statusText, replayURL string) {
	if jsonMode {
		return
	}
	label := fmt.Sprintf("── REPLAY #%d ──", id)
	if session != "" {
		label = fmt.Sprintf("── REPLAY #%d (session %s) ──", seq, session)
	}
	var b strings.Builder
	b.WriteString("\n" + paint(colCyan, label) + "\n")
	fmt.Fprintf(&b, "Original:  %s %s  →  %s\n", sanitizeLine(method), sanitizeLine(origURL), sanitizeLine(statusText))
	fmt.Fprintf(&b, "Replaying: %s %s\n", sanitizeLine(method), sanitizeLine(replayURL))
	emitText(b.String())
}

// replayOne re-issues a single v1 exchange and reports how the response
// compares.
func replayOne(client *http.Client, ex *recordedExchange, targetBase string) replayResult {
	res := replayResult{ID: ex.ID, Method: ex.Method, RecordedStatus: ex.Status}
	replayURL := rebase(ex.URL, targetBase)
	res.URL = replayURL
	replayHeading(ex.ID, 0, "", ex.Method, ex.URL, ex.StatusText, replayURL)

	reqHeader := make(http.Header, len(ex.ReqHeaders))
	for k, v := range ex.ReqHeaders {
		reqHeader.Set(k, v)
	}
	switch {
	case isGRPCContentType(reqHeader.Get("Content-Type")):
		res.Skipped = grpcReplaySkip
	case ex.ReqBodyTruncated:
		res.Skipped = truncatedReqSkip
	case len(splitEncodings(reqHeader.Get("Content-Encoding"))) > 0 && ex.ReqBody != "":
		res.Skipped = encodedReqSkip
	case isBodyPlaceholder(ex.ReqBody):
		res.Skipped = placeholderSkip
	}
	if res.Skipped != "" {
		emitReplayResult(res, "")
		return res
	}

	resp, dur, err := sendReplay(client, ex.Method, replayURL, reqHeader, []byte(ex.ReqBody))
	res.DurationMs = dur.Milliseconds()
	if err != nil {
		res.Err = err.Error()
		emitReplayResult(res, "")
		return res
	}
	defer resp.Body.Close()
	raw, overflow := readCapped(resp.Body)

	res.ActualStatus = resp.StatusCode
	res.StatusMatch = resp.StatusCode == ex.Status

	// v1 stored the display view of the body, so compare like with like: a
	// binary body is a placeholder on both sides, a compressed one decoded.
	newBody := strings.TrimSpace(decodeBody(resp.Header, raw, overflow).Text)
	if ex.RespBodyTruncated {
		// Only a prefix was recorded, so only a prefix can be compared.
		res.BodyMatch = strings.HasPrefix(newBody, strings.TrimSpace(ex.RespBody))
	} else {
		res.BodyMatch = strings.TrimSpace(ex.RespBody) == newBody
	}

	emitReplayResult(res, newBody)
	return res
}

// isBodyPlaceholder recognises the stand-ins v1 recorded for bodies it did
// not store: "[binary data, 300+ bytes]", "[gzip, 12+ bytes]", "[gRPC: …]".
func isBodyPlaceholder(s string) bool {
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return false
	}
	return strings.HasPrefix(s, "[binary data, ") || strings.HasPrefix(s, "[gRPC: ") ||
		(strings.Contains(s, ", ") && strings.HasSuffix(s, "+ bytes]"))
}

// replayV2 re-issues a single v2 exchange. The recording holds the request's
// bytes, so the request is reproduced exactly, and the response is compared
// byte for byte after removing its Content-Encoding.
func replayV2(client *http.Client, ex *recordV2, targetBase string) replayResult {
	res := replayResult{ID: ex.Seq, Method: ex.Method, RecordedStatus: ex.Status}
	replayURL := rebase(ex.URL, targetBase)
	res.URL = replayURL
	replayHeading(ex.Seq, ex.Seq, ex.Session, ex.Method, ex.URL, ex.StatusText, replayURL)

	reqHeader := ex.ReqHeaders.header()
	switch {
	case ex.Kind == "websocket":
		res.Skipped = websocketReplaySkip
	case ex.Error != "":
		res.Skipped = failedReplaySkip
	case ex.ReqBody != nil && ex.ReqBody.Truncated:
		res.Skipped = truncatedReqSkip
	case ex.Redacted && (ex.ReqHeaders.hasSensitive() || redactedURL(ex.URL)):
		res.Skipped = redactedReplaySkip
	}
	if res.Skipped != "" {
		emitReplayResult(res, "")
		return res
	}

	var body []byte
	if ex.ReqBody != nil {
		b, err := decodeBytes(ex.ReqBody.Encoding, ex.ReqBody.Data)
		if err != nil {
			res.Err = "request body: " + err.Error()
			emitReplayResult(res, "")
			return res
		}
		body = b
	}

	grpc := isGRPCContentType(reqHeader.Get("Content-Type"))
	c := client
	if grpc && strings.HasPrefix(replayURL, "http://") {
		// A cleartext gRPC server speaks only HTTP/2.
		c = h2cClient
	}
	resp, dur, err := sendReplay(c, ex.Method, replayURL, reqHeader, body)
	res.DurationMs = dur.Milliseconds()
	if err != nil {
		res.Err = err.Error()
		emitReplayResult(res, "")
		return res
	}
	defer resp.Body.Close()
	raw, overflow := readCapped(resp.Body)

	res.ActualStatus = resp.StatusCode
	res.StatusMatch = resp.StatusCode == ex.Status
	if grpc {
		recHeaders, recTrailers := ex.RespHeaders.header(), ex.RespTrailers.header()
		res.RecordedGRPCStatus = grpcStatus(recHeaders, recTrailers)
		res.ActualGRPCStatus = grpcStatus(resp.Header, resp.Trailer)
		res.StatusMatch = res.StatusMatch && res.RecordedGRPCStatus == res.ActualGRPCStatus
	}

	var recorded []byte
	recTruncated := false
	if ex.RespBody != nil {
		rb, err := decodeBytes(ex.RespBody.Encoding, ex.RespBody.Data)
		if err != nil {
			res.Err = "recorded response body: " + err.Error()
			emitReplayResult(res, "")
			return res
		}
		recorded, recTruncated = decodeContent(ex.RespHeaders.header().Get("Content-Encoding"), rb, ex.RespBody.Truncated)
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

// sendReplay sends one replayed request. Hop-by-hop headers and framing are
// left to the transport, as they would be for any new request.
func sendReplay(client *http.Client, method, u string, h http.Header, body []byte) (*http.Response, time.Duration, error) {
	var r io.Reader
	if len(body) > 0 {
		r = bytes.NewReader(body)
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
	if len(splitEncodings(encoding)) == 0 {
		return raw, truncated
	}
	res, err := decompressBody(encoding, raw)
	if err != nil {
		return raw, truncated
	}
	return res.Data, truncated || res.Truncated
}

// decodeForCompare decompresses a replayed response body so it can be compared
// against a recording that stores bodies already decoded.
func decodeForCompare(h http.Header, body []byte) string {
	b, _ := decodeContent(h.Get("Content-Encoding"), body, false)
	return string(b)
}

// grpcStatus returns a gRPC call's status code, from the trailers or, for a
// trailers-only response, the headers.
func grpcStatus(headers, trailers http.Header) string {
	if s := trailers.Get("Grpc-Status"); s != "" {
		return s
	}
	return headers.Get("Grpc-Status")
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
		fmt.Fprintf(&b, "  %s: %s\n", paint(colRed, "FAIL"), sanitizeLine(res.Err))
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
			fmt.Fprintf(&b, "    now: %s\n", sanitizeLine(newBody))
		}
	}
	emitText(b.String())
}
