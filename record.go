package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// recordedExchange is one request/response pair serialised to NDJSON.
// The file contains one JSON object per line; "type" distinguishes them.
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
	DurationMs  int64             `json:"duration_ms"`
}

// recordFile is the open file used by the proxy when --record is active.
var (
	recordFile    *os.File
	recordEncoder *json.Encoder

	// pendingRecords buffers request data until the response arrives.
	pendingRecords   = make(map[int]*recordedExchange)
	pendingRecordsMu sync.Mutex
)

// openRecordFile opens (or creates) the NDJSON recording file.
func openRecordFile(path string) error {
	// 0600: recordings carry whole request headers, including Authorization
	// values and cookies, so they must not be world-readable.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	recordFile = f
	recordEncoder = json.NewEncoder(f)
	return nil
}

// recordRequestBody stores request data once its body has finished streaming.
func recordRequestBody(reqID int, f requestFacts, body string) {
	e := &recordedExchange{
		ID:         reqID,
		Time:       f.startTime.Format(time.RFC3339),
		Method:     f.method,
		URL:        f.rawURL,
		ReqHeaders: flattenHeaders(f.headers),
		ReqBody:    body,
	}
	pendingRecordsMu.Lock()
	pendingRecords[reqID] = e
	pendingRecordsMu.Unlock()
}

// recordResponseBody completes the pending entry and writes it to disk. It runs
// after the response body has finished streaming, so the record is only written
// once the whole exchange is known.
func recordResponseBody(reqID int, f responseFacts, body string) {
	pendingRecordsMu.Lock()
	e, ok := pendingRecords[reqID]
	if ok {
		delete(pendingRecords, reqID)
	}
	pendingRecordsMu.Unlock() //nolint:govet
	if !ok {
		return
	}

	e.Status = f.status
	e.StatusText = f.statusText
	e.RespHeaders = flattenHeaders(f.headers)
	e.RespBody = body
	e.DurationMs = f.duration.Milliseconds()

	if recordEncoder != nil {
		recordEncoder.Encode(e) //nolint:errcheck
	}
}

// ── Replay ───────────────────────────────────────────────────────────────────

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
}

// Differs reports whether the replayed response deviated from the recording.
func (r replayResult) Differs() bool {
	return r.Err != "" || !r.StatusMatch || !r.BodyMatch
}

// replayFile reads an NDJSON recording and replays each exchange.
// If targetBase is non-empty it is used as the URL prefix (scheme+host),
// replacing the original host. Results are printed to stdout.
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

	client := &http.Client{
		Transport: &http.Transport{
			// Mirrors the proxy's policy so a recording captured from a
			// self-signed or internal-CA host can still be replayed.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureUpstream}, //nolint:gosec // opt-in via --insecure-upstream
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	n, errs, diffs := 0, 0, 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var ex recordedExchange
		if err := json.Unmarshal(line, &ex); err != nil {
			fmt.Fprintf(os.Stderr, "replay: malformed line: %v\n", err)
			errs++
			continue
		}

		if n > 0 && delayBetween > 0 {
			time.Sleep(delayBetween)
		}

		res := replayOne(client, &ex, targetBase)
		if res.Differs() {
			diffs++
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "replay: read error: %v\n", err)
		return 1
	}
	if !jsonMode {
		fmt.Printf("\n%s replayed %d request(s), %d error(s), %d diff(s)\n",
			strings.Repeat("─", 60), n, errs, diffs)
	}
	if errs > 0 {
		return 1
	}
	if failOnDiff && diffs > 0 {
		return 2
	}
	return 0
}

// replayOne re-issues a single recorded exchange and reports how the response
// compares. Output goes to stdout as text, or as one NDJSON object when
// --format json is set.
func replayOne(client *http.Client, ex *recordedExchange, targetBase string) replayResult {
	res := replayResult{ID: ex.ID, Method: ex.Method, RecordedStatus: ex.Status}
	replayURL := ex.URL
	if targetBase != "" {
		// Replace scheme+host in the original URL with targetBase,
		// preserving path, query string, and fragment.
		rest := ex.URL
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
		replayURL = strings.TrimRight(targetBase, "/") + rest
	}
	res.URL = replayURL

	if !jsonMode {
		fmt.Printf("\n\033[36m── REPLAY #%d ──\033[0m\n", ex.ID)
		fmt.Printf("Original:  %s %s  →  %s\n", ex.Method, ex.URL, ex.StatusText)
		fmt.Printf("Replaying: %s %s\n", ex.Method, replayURL)
	}

	var bodyReader io.Reader
	if ex.ReqBody != "" {
		bodyReader = strings.NewReader(ex.ReqBody)
	}

	req, err := http.NewRequest(ex.Method, replayURL, bodyReader)
	if err != nil {
		res.Err = err.Error()
		emitReplayResult(res, "")
		return res
	}
	for k, v := range ex.ReqHeaders {
		req.Header.Set(k, v)
	}
	// Remove host-specific headers that would break the replayed request.
	req.Header.Del("Host")

	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start)
	res.DurationMs = dur.Milliseconds()
	if err != nil {
		res.Err = err.Error()
		emitReplayResult(res, "")
		return res
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(captureMaxBody)))

	res.ActualStatus = resp.StatusCode
	res.StatusMatch = resp.StatusCode == ex.Status

	newBody := strings.TrimSpace(decodeForCompare(resp.Header, respBody))
	res.BodyMatch = strings.TrimSpace(ex.RespBody) == newBody

	emitReplayResult(res, newBody)
	return res
}

// decodeForCompare decompresses a replayed response body so it can be compared
// against the recording, which stores bodies already decoded. Without this,
// every compressed endpoint would report a body difference on every replay.
// Bodies that cannot be decoded are compared as-is.
func decodeForCompare(h http.Header, body []byte) string {
	enc := h.Get("Content-Encoding")
	if len(splitEncodings(enc)) == 0 {
		return string(body)
	}
	res, err := decompressBody(enc, body)
	if err != nil {
		return string(body)
	}
	return string(res.Data)
}

// emitReplayResult renders one replay outcome, as coloured text or NDJSON.
func emitReplayResult(res replayResult, newBody string) {
	if jsonMode {
		jsonEncMu.Lock()
		jsonEnc.Encode(res) //nolint:errcheck
		jsonEncMu.Unlock()
		return
	}

	if res.Err != "" {
		fmt.Fprintf(os.Stderr, "  \033[31mFAIL\033[0m: %v\n", res.Err)
		return
	}

	statusIcon := "\033[32m✓\033[0m"
	if !res.StatusMatch {
		statusIcon = "\033[31m✗\033[0m"
	}
	fmt.Printf("  Status:  %s  recorded=%d  actual=%d  (%dms)\n",
		statusIcon, res.RecordedStatus, res.ActualStatus, res.DurationMs)

	if res.BodyMatch {
		fmt.Printf("  Body:    \033[32m✓ unchanged\033[0m\n")
		return
	}
	fmt.Printf("  Body:    \033[33m≠ changed\033[0m\n")
	if len(newBody) > 200 {
		newBody = newBody[:200] + "…"
	}
	fmt.Printf("    now: %s\n", newBody)
}
