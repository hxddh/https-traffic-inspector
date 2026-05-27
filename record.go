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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	recordFile = f
	recordEncoder = json.NewEncoder(f)
	return nil
}

// recordRequest stores request data in the pending map.
func recordRequest(reqID int, req *http.Request, body string) {
	e := &recordedExchange{
		ID:         reqID,
		Time:       time.Now().Format(time.RFC3339),
		Method:     req.Method,
		URL:        req.URL.String(),
		ReqHeaders: flattenHeaders(req.Header),
		ReqBody:    body,
	}
	pendingRecordsMu.Lock()
	pendingRecords[reqID] = e
	pendingRecordsMu.Unlock()
}

// recordResponse completes the pending entry and writes it to disk.
func recordResponse(reqID int, resp *http.Response, body string, dur time.Duration) {
	pendingRecordsMu.Lock()
	e, ok := pendingRecords[reqID]
	if ok {
		delete(pendingRecords, reqID)
	}
	pendingRecordsMu.Unlock() //nolint:govet
	if !ok {
		return
	}

	e.Status = resp.StatusCode
	e.StatusText = resp.Status
	e.RespHeaders = flattenHeaders(resp.Header)
	e.RespBody = body
	e.DurationMs = dur.Milliseconds()

	if recordEncoder != nil {
		recordEncoder.Encode(e) //nolint:errcheck
	}
}

// ── Replay ───────────────────────────────────────────────────────────────────

// replayFile reads an NDJSON recording and replays each exchange.
// If targetBase is non-empty it is used as the URL prefix (scheme+host),
// replacing the original host. Results are printed to stdout.
func replayFile(path, targetBase string, delayBetween time.Duration) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: cannot open %s: %v\n", path, err)
		return 1
	}
	defer f.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	n, errs := 0, 0
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

		replayOne(client, &ex, targetBase)
		n++
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "replay: read error: %v\n", err)
		return 1
	}
	fmt.Printf("\n%s replayed %d request(s), %d error(s)\n",
		strings.Repeat("─", 60), n, errs)
	if errs > 0 {
		return 1
	}
	return 0
}

func replayOne(client *http.Client, ex *recordedExchange, targetBase string) {
	replayURL := ex.URL
	if targetBase != "" {
		// Replace scheme+host in the original URL with targetBase.
		rest := ex.URL
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
			if j := strings.Index(rest, "/"); j >= 0 {
				rest = rest[j:]
			} else {
				rest = "/"
			}
		}
		replayURL = strings.TrimRight(targetBase, "/") + rest
	}

	fmt.Printf("\n\033[36m── REPLAY #%d ──\033[0m\n", ex.ID)
	fmt.Printf("Original:  %s %s  →  %s\n", ex.Method, ex.URL, ex.StatusText)
	fmt.Printf("Replaying: %s %s\n", ex.Method, replayURL)

	var bodyReader io.Reader
	if ex.ReqBody != "" {
		bodyReader = strings.NewReader(ex.ReqBody)
	}

	req, err := http.NewRequest(ex.Method, replayURL, bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error building request: %v\n", err)
		return
	}
	for k, v := range ex.ReqHeaders {
		req.Header.Set(k, v)
	}
	// Remove host-specific headers that would break the replayed request.
	req.Header.Del("Host")

	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  \033[31mFAIL\033[0m: %v\n", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))

	// Compare status.
	statusMatch := resp.StatusCode == ex.Status
	statusIcon := "\033[32m✓\033[0m"
	if !statusMatch {
		statusIcon = "\033[31m✗\033[0m"
	}
	fmt.Printf("  Status:  %s  recorded=%d  actual=%d  (%v)\n",
		statusIcon, ex.Status, resp.StatusCode, dur.Round(time.Millisecond))

	// Print response body diff summary.
	origBody := strings.TrimSpace(ex.RespBody)
	newBody := strings.TrimSpace(string(respBody))
	if origBody == newBody {
		fmt.Printf("  Body:    \033[32m✓ unchanged\033[0m\n")
	} else {
		fmt.Printf("  Body:    \033[33m≠ changed\033[0m\n")
		if len(newBody) > 200 {
			newBody = newBody[:200] + "…"
		}
		fmt.Printf("    now: %s\n", newBody)
	}
}
