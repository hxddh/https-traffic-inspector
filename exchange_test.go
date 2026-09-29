package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Regression: a record was written only when the response finished after the
// request had. A server that answers before reading the whole upload -- a 413,
// an auth failure -- finishes the response first, and the exchange was
// silently left out of --record and --har.
func TestRecord_ResponseBeforeRequestFinishes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, "too large") //nolint:errcheck
	}))
	defer upstream.Close()

	recPath := t.TempDir() + "/rec.ndjson"
	savedRM := recordMode
	recordMode = true
	savedCaptures := captures
	captures = newExchangeJoiner()
	if err := openRecordFile(recPath); err != nil {
		t.Fatal(err)
	}
	defer func() {
		recordFile.Close() //nolint:errcheck
		recordFile, recordEncoder = nil, nil
		recordMode = savedRM
		captures = savedCaptures
	}()

	proxyURL, _ := url.Parse("http://" + startTestProxy(t))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// An upload that keeps trickling well after the server has answered.
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 4; i++ {
			fmt.Fprintf(pw, "chunk%d\n", i)
			time.Sleep(150 * time.Millisecond)
		}
		pw.Close() //nolint:errcheck
	}()
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/upload", pr)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()              //nolint:errcheck

	// The request half lands once the upload is abandoned or finishes.
	var recs []recordedExchange
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recs = readRecords(t, recPath)
		if len(recs) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(recs) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(recs))
	}
	if recs[0].Status != http.StatusRequestEntityTooLarge || recs[0].RespBody != "too large" {
		t.Errorf("record = %+v", recs[0])
	}
	if n := captures.pending(); n != 0 {
		t.Errorf("%d halves left pending after the exchange completed", n)
	}
}

func readRecords(t *testing.T, path string) []recordedExchange {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []recordedExchange
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e recordedExchange
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad record line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

// Regression: when an upstream request failed, the pending entry was deleted
// first and the request half, arriving afterwards as the transport closed the
// body, was stored again and never removed.
func TestExchangeJoiner_DropBeforeRequestLeavesNothingBehind(t *testing.T) {
	j := newExchangeJoiner()
	j.drop(7)
	j.addRequest(7, capturedRequest{})
	if n := j.pending(); n != 0 {
		t.Errorf("pending = %d after a dropped exchange's late request half, want 0", n)
	}

	j.addRequest(8, capturedRequest{})
	j.drop(8)
	if n := j.pending(); n != 0 {
		t.Errorf("pending = %d after dropping an exchange with its request half present, want 0", n)
	}
}

// A client that stops reading and closes the body leaves only a prefix; the
// sample must not be presented as the whole body.
func TestSampler_ClosedBeforeEOFIsIncomplete(t *testing.T) {
	var got bodyView
	h := http.Header{"Content-Type": {"text/plain"}}
	body := io.NopCloser(strings.NewReader("hello world"))
	sampleBody(&body, h, -1, func(v bodyView) { got = v })

	buf := make([]byte, 5)
	io.ReadFull(body, buf) //nolint:errcheck
	body.Close()           //nolint:errcheck

	if got.Text != "hello" || !got.Truncated {
		t.Errorf("got %+v, want the prefix \"hello\" marked truncated", got)
	}
	if !strings.HasSuffix(truncateForDisplay(got), truncationMarker) {
		t.Errorf("display %q lacks the truncation marker", truncateForDisplay(got))
	}
}

func TestSampler_ReadToEOFIsComplete(t *testing.T) {
	var got bodyView
	h := http.Header{"Content-Type": {"text/plain"}}
	body := io.NopCloser(strings.NewReader("hello world"))
	sampleBody(&body, h, -1, func(v bodyView) { got = v })
	io.Copy(io.Discard, body) //nolint:errcheck
	body.Close()              //nolint:errcheck
	if got.Text != "hello world" || got.Truncated {
		t.Errorf("got %+v, want the whole body, not truncated", got)
	}
}

// Replay can only compare the part of a body that was recorded.
func TestReplay_TruncatedRecordingComparesPrefix(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello world, and much more") //nolint:errcheck
	}))
	defer target.Close()

	path := writeRecording(t, recordedExchange{
		ID: 1, Method: "GET", URL: target.URL + "/",
		Status: 200, StatusText: "200 OK",
		RespBody: "hello world", RespBodyTruncated: true,
	})
	if code := replayFile(path, "", 0, true); code != 0 {
		t.Errorf("code = %d, want 0: the recorded prefix matches", code)
	}
}

// Regression: events went through a 512-slot channel with a non-blocking
// send, so a burst larger than that was silently dropped and the TUI showed
// entries stuck as pending.
func TestEventQueue_KeepsEveryEventInOrder(t *testing.T) {
	q := newEventQueue()
	const n = 5000
	for i := 0; i < n; i++ {
		q.push(i)
	}
	for i := 0; i < n; i++ {
		if got := q.pop(); got != i {
			t.Fatalf("pop %d = %v", i, got)
		}
	}

	done := make(chan any)
	go func() { done <- q.pop() }()
	time.Sleep(20 * time.Millisecond)
	q.push("late")
	select {
	case got := <-done:
		if got != "late" {
			t.Errorf("got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pop did not wake for an event pushed while it waited")
	}
}

// A consumer that stops once it has the declared length has the whole body,
// even though it never read EOF; that must not be reported as truncated.
func TestSampler_DeclaredLengthReachedIsComplete(t *testing.T) {
	var got bodyView
	fired := 0
	h := http.Header{"Content-Type": {"text/plain"}}
	body := io.NopCloser(strings.NewReader("hello"))
	sampleBody(&body, h, 5, func(v bodyView) { fired++; got = v })

	buf := make([]byte, 5)
	io.ReadFull(body, buf) //nolint:errcheck
	body.Close()           //nolint:errcheck

	if fired != 1 || got.Text != "hello" || got.Truncated {
		t.Errorf("fired=%d got=%+v, want one complete \"hello\"", fired, got)
	}
}

// Regression: forwardRequest deferred resp.Body.Close() before logResponse
// wrapped the body in the sampler, so the deferred call closed the original
// underneath it. When the copy to the client stopped before EOF -- a client
// that hangs up once it has every byte -- the sampler never reported and the
// exchange vanished from the output, the recording and the HAR. Measured: 2 in
// 120 single-request runs lost their only exchange.
func TestForward_ResponseLoggedWhenCopyStopsBeforeEOF(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "partial") //nolint:errcheck
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never finishes on its own
	}))
	defer upstream.Close()

	savedHM, savedCaptures := harMode, captures
	harMode, captures = true, newExchangeJoiner()
	harEntriesMu.Lock()
	harEntries = nil
	harEntriesMu.Unlock()
	defer func() { harMode, captures = savedHM, savedCaptures }()

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.RequestURI = ""
	forwardRequest(failingWriter{httptest.NewRecorder()}, req, upstreamClient)

	harEntriesMu.Lock()
	defer harEntriesMu.Unlock()
	if len(harEntries) != 1 {
		t.Fatalf("HAR has %d entries, want 1", len(harEntries))
	}
	if c := harEntries[0].Response.Content; c.Comment == "" {
		t.Errorf("a body cut short should be marked truncated, got %+v", c)
	}
}

// failingWriter accepts headers but fails every body write, as a connection
// the client has closed does.
type failingWriter struct{ *httptest.ResponseRecorder }

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
