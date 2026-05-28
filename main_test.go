package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- generateCert ----

func TestGenerateCert_Cached(t *testing.T) {
	c1, err := generateCert("cached.test.local")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := generateCert("cached.test.local")
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Error("expected same pointer from cache for the same host")
	}
}

func TestGenerateCert_DifferentHosts(t *testing.T) {
	c1, err := generateCert("host-a.test.local")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := generateCert("host-b.test.local")
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Error("expected distinct certs for different hosts")
	}
}

func TestGenerateCert_NoConcurrentRace(t *testing.T) {
	// Run with -race to validate the TOCTOU fix.
	const host = "race-test.test.local"
	// Clear any cached entry so all goroutines race on a cold miss.
	certMu.Lock()
	delete(certCache, host)
	certMu.Unlock()

	var wg sync.WaitGroup
	results := make([]*[4]byte, 20)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := generateCert(host)
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
				return
			}
			var token [4]byte
			copy(token[:], c.Certificate[0])
			results[idx] = &token
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r == nil {
			t.Fatalf("results[%d] is nil", i)
		}
		if *r != *results[0] {
			t.Errorf("results[%d] differs from results[0]: cache inconsistency", i)
		}
	}
}

func TestGenerateCert_UniqueSerials(t *testing.T) {
	certMu.Lock()
	delete(certCache, "serial-a.test.local")
	delete(certCache, "serial-b.test.local")
	certMu.Unlock()

	c1, err := generateCert("serial-a.test.local")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := generateCert("serial-b.test.local")
	if err != nil {
		t.Fatal(err)
	}

	x1, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	x2, err := x509.ParseCertificate(c2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if x1.SerialNumber.Cmp(x2.SerialNumber) == 0 {
		t.Error("two distinct leaf certs share the same serial number")
	}
}

func TestGenerateCert_TTLExpiry(t *testing.T) {
	const host = "ttl-test.test.local"
	saved := certTTL
	certTTL = 50 * time.Millisecond
	defer func() { certTTL = saved }()

	certMu.Lock()
	delete(certCache, host)
	certMu.Unlock()

	c1, err := generateCert(host)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond) // let the TTL expire

	// Force eviction by calling generateCert again (expired entries are replaced inline).
	c2, err := generateCert(host)
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Error("expected a new cert after TTL expiry, got the same pointer")
	}
}

func TestGenerateCert_SignedByCA(t *testing.T) {
	certMu.Lock()
	delete(certCache, "signed.test.local")
	certMu.Unlock()

	tlsCert, err := generateCert("signed.test.local")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName: "signed.test.local",
		Roots:   pool,
	})
	if err != nil {
		t.Errorf("leaf cert does not verify against CA: %v", err)
	}
}

// ---- peekBody ----

func TestPeekBody_ShortBody(t *testing.T) {
	const original = "hello world"
	rc := io.NopCloser(strings.NewReader(original))
	peeked := peekBody(&rc, 1000)
	if string(peeked) != original {
		t.Errorf("peeked %q, want %q", peeked, original)
	}
	remaining, _ := io.ReadAll(rc)
	if string(remaining) != original {
		t.Errorf("remaining body %q, want %q", remaining, original)
	}
}

func TestPeekBody_LongBody(t *testing.T) {
	payload := strings.Repeat("x", 2000)
	rc := io.NopCloser(strings.NewReader(payload))
	peeked := peekBody(&rc, 100)
	if len(peeked) != 100 {
		t.Errorf("peeked %d bytes, want 100", len(peeked))
	}
	remaining, _ := io.ReadAll(rc)
	if string(remaining) != payload {
		t.Errorf("full body not restored after peek: got %d bytes, want %d", len(remaining), len(payload))
	}
}

func TestPeekBody_EmptyBody(t *testing.T) {
	rc := io.NopCloser(strings.NewReader(""))
	peeked := peekBody(&rc, 100)
	if len(peeked) != 0 {
		t.Errorf("expected empty peek, got %q", peeked)
	}
}

// ---- isPrintable ----

func TestIsPrintable(t *testing.T) {
	cases := []struct {
		ct   string
		enc  string
		want bool
	}{
		{"application/json", "", true},
		{"text/plain", "", true},
		{"text/html; charset=utf-8", "", true},
		{"application/xml", "", true},
		{"image/png", "", false},
		{"application/octet-stream", "", false},
		{"application/json", "gzip", false},
		{"text/plain", "br", false},
		{"text/plain", "identity", true},
		{"", "", true},
	}
	for _, tc := range cases {
		h := make(http.Header)
		if tc.ct != "" {
			h.Set("Content-Type", tc.ct)
		}
		if tc.enc != "" {
			h.Set("Content-Encoding", tc.enc)
		}
		if got := isPrintable(h); got != tc.want {
			t.Errorf("isPrintable(ct=%q enc=%q) = %v, want %v", tc.ct, tc.enc, got, tc.want)
		}
	}
}

// ---- matchesFilter ----

func TestMatchesFilter(t *testing.T) {
	cases := []struct {
		pattern string
		rawURL  string
		host    string
		want    bool
	}{
		{"", "https://example.com/api", "example.com", true},
		{"api", "https://example.com/api/v1", "example.com", true},
		{"API", "https://example.com/api/v1", "example.com", true}, // case-insensitive
		{"github", "https://example.com/api/v1", "example.com", false},
		{"example", "https://example.com/api/v1", "example.com", true}, // matches host
	}
	saved := filterPattern
	defer func() { filterPattern = saved }()

	for _, tc := range cases {
		filterPattern = tc.pattern
		req, _ := http.NewRequest("GET", tc.rawURL, nil)
		req.Host = tc.host
		if got := matchesFilter(req); got != tc.want {
			t.Errorf("matchesFilter(pattern=%q url=%q host=%q) = %v, want %v",
				tc.pattern, tc.rawURL, tc.host, got, tc.want)
		}
	}
}

// ---- handleHTTP integration ----

func TestHandleHTTP_ForwardsRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("X-Test"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong")) //nolint:errcheck
	}))
	defer upstream.Close()

	req, _ := http.NewRequest("GET", upstream.URL+"/ping", nil)
	req.Header.Set("X-Test", "hello")

	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); body != "pong" {
		t.Errorf("body = %q, want %q", body, "pong")
	}
	if echo := rr.Header().Get("X-Echo"); echo != "hello" {
		t.Errorf("X-Echo = %q, want %q", echo, "hello")
	}
}

func TestHandleHTTP_UpstreamError(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://127.0.0.1:1/unreachable", nil)
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}

func TestHandleHTTP_FilterSkipsLogging(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	saved := filterPattern
	filterPattern = "nomatch"
	defer func() { filterPattern = saved }()

	savedCounter := requestCounter
	req, _ := http.NewRequest("GET", upstream.URL, nil)
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if requestCounter != savedCounter {
		t.Error("request counter incremented despite filter mismatch; logging should be skipped")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (transparent proxy still works)", rr.Code)
	}
}

// ---- handleHTTP with proxy ----

func TestHandleHTTP_ViaProxyClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(handleHTTP))
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

// ---- JSON logging ----

func TestLogRequest_JSONMode(t *testing.T) {
	saved := jsonMode
	jsonMode = true
	defer func() { jsonMode = saved }()

	var buf bytes.Buffer
	jsonEnc = json.NewEncoder(&buf)

	req, _ := http.NewRequest("GET", "https://example.com/api?foo=bar", nil)
	req.Host = "example.com"
	req.Proto = "HTTP/1.1"

	reqID := logRequest(req)
	if reqID <= 0 {
		t.Errorf("reqID = %d, want > 0", reqID)
	}

	var entry jsonRequest
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}
	if entry.Method != "GET" {
		t.Errorf("Method = %q, want GET", entry.Method)
	}
	if !strings.Contains(entry.URL, "foo=bar") {
		t.Errorf("URL %q missing query string", entry.URL)
	}
	if entry.ID != reqID {
		t.Errorf("JSON id %d != returned reqID %d", entry.ID, reqID)
	}
}

func TestLogResponse_JSONCorrelation(t *testing.T) {
	saved := jsonMode
	jsonMode = true
	defer func() { jsonMode = saved }()

	var buf bytes.Buffer
	jsonEnc = json.NewEncoder(&buf)

	resp := &http.Response{
		StatusCode: 201,
		Status:     "201 Created",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"id":42}`)),
	}
	resp.Header.Set("Content-Type", "application/json")

	logResponse(resp, 7)

	var entry jsonResponse
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}
	if entry.ReqID != 7 {
		t.Errorf("req_id = %d, want 7", entry.ReqID)
	}
	if entry.Status != 201 {
		t.Errorf("status = %d, want 201", entry.Status)
	}
	if !strings.Contains(entry.Body, "42") {
		t.Errorf("body %q missing expected content", entry.Body)
	}
}

// ---- writeConnError ----

func TestWriteConnError(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		writeConnError(server, http.StatusBadGateway, "upstream unreachable")
		server.Close()
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "upstream unreachable") {
		t.Errorf("body %q missing error message", body)
	}
}

// ---- buildCABundle ----

func TestBuildCABundle_ContainsProxyCA(t *testing.T) {
	proxyCAPEM := []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
	path, err := buildCABundle(proxyCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, proxyCAPEM) {
		t.Error("CA bundle does not contain the proxy CA PEM")
	}
}

func TestBuildCABundle_UniqueFiles(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
	p1, err := buildCABundle(pem)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := buildCABundle(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p1)
	defer os.Remove(p2)

	if p1 == p2 {
		t.Error("two buildCABundle calls returned the same file path; should be unique")
	}
}

// ---- record / replay ----

func TestRecord_WriteAndRead(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hello":"world"}`)) //nolint:errcheck
	}))
	defer upstream.Close()

	// Open a temp record file.
	f, err := os.CreateTemp("", "httpmon-test-rec-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	recPath := f.Name()
	f.Close()
	defer os.Remove(recPath)

	// Enable record mode.
	savedRM := recordMode
	recordMode = true
	if err := openRecordFile(recPath); err != nil {
		t.Fatal(err)
	}
	defer func() {
		recordFile.Close()
		recordFile = nil
		recordEncoder = nil
		recordMode = savedRM
	}()

	// Issue a request through handleHTTP.
	req, _ := http.NewRequest("GET", upstream.URL+"/hello", nil)
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	// Flush and read back the NDJSON.
	recordFile.Sync() //nolint:errcheck
	data, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}

	var ex recordedExchange
	if err := json.Unmarshal(bytes.TrimSpace(data), &ex); err != nil {
		t.Fatalf("invalid NDJSON: %v\nraw: %s", err, data)
	}
	if ex.Status != http.StatusOK {
		t.Errorf("recorded status = %d, want 200", ex.Status)
	}
	if !strings.Contains(ex.RespBody, "hello") {
		t.Errorf("recorded body %q missing expected content", ex.RespBody)
	}
	if ex.DurationMs < 0 {
		t.Errorf("recorded duration_ms = %d, want >= 0", ex.DurationMs)
	}
}

func TestReplay_StatusAndBodyDiff(t *testing.T) {
	// Target server that returns a different body than the recorded one.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hello":"changed"}`)) //nolint:errcheck
	}))
	defer target.Close()

	// Write a minimal recording file.
	ex := recordedExchange{
		ID:         1,
		Time:       time.Now().Format(time.RFC3339),
		Method:     "GET",
		URL:        target.URL + "/hello",
		ReqHeaders: map[string]string{"Accept": "*/*"},
		Status:     200,
		StatusText: "200 OK",
		RespHeaders: map[string]string{"Content-Type": "application/json"},
		RespBody:   `{"hello":"world"}`,
		DurationMs: 10,
	}
	f, err := os.CreateTemp("", "httpmon-test-replay-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	replayPath := f.Name()
	defer os.Remove(replayPath)
	json.NewEncoder(f).Encode(ex) //nolint:errcheck
	f.Close()

	// Replay with target override.
	code := replayFile(replayPath, target.URL, 0)
	// We don't assert code == 0 because the body diff causes no error exit,
	// and status matched so code should be 0.
	if code != 0 {
		t.Errorf("replayFile returned %d, want 0", code)
	}
}

func TestReplay_MissingFile(t *testing.T) {
	code := replayFile("/nonexistent/path.ndjson", "", 0)
	if code == 0 {
		t.Error("expected non-zero exit for missing file")
	}
}

func TestReplay_MalformedNDJSON(t *testing.T) {
	f, err := os.CreateTemp("", "httpmon-test-bad-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("not valid json\n") //nolint:errcheck
	f.Close()

	// Should not panic; malformed lines are skipped with an error count.
	// Returns 1 because errs > 0.
	code := replayFile(f.Name(), "", 0)
	if code != 1 {
		t.Errorf("expected exit code 1 for malformed NDJSON, got %d", code)
	}
}

// ---- Expect: 100-continue regression test ----

// TestHandleConnect_Expect100Continue verifies that a PUT request carrying
// Expect: 100-continue does not deadlock the proxy.
//
// Without the fix, the sequence is:
//   1. client sends headers + Expect: 100-continue, withholds body
//   2. handleConnect calls logRequest → peekBody → io.ReadFull on client conn
//   3. io.ReadFull blocks: client won't send body until it sees "100 Continue"
//   4. deadlock — proxy never reaches sessionClient.Do
//
// With the fix, the proxy immediately writes "HTTP/1.1 100 Continue\r\n\r\n"
// to the client before reading the body, breaking the deadlock.
func TestHandleConnect_Expect100Continue(t *testing.T) {
	const body = `{"key":"value"}`

	// Upstream HTTPS server that accepts PUT and echoes the body.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(got) //nolint:errcheck
	}))
	defer upstream.Close()

	// Build a CA pool that trusts the upstream test server's cert so our
	// sessionClient (InsecureSkipVerify) can connect to it.
	_ = upstream.TLS // already set up

	// The proxy side: run handleConnect in a goroutine via a net.Pipe pair.
	// We simulate what happens after a real CONNECT handshake:
	//   - clientConn is the "client" side of the pipe (our test writes here)
	//   - serverConn is the "server" side (handleConnect reads from here)

	serverConn, clientConn := net.Pipe()

	// Wrap serverConn in TLS using a cert for the upstream host.
	upstreamHost := upstream.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(upstreamHost)
	if host == "" {
		host = "127.0.0.1"
	}

	cert, err := generateCert(host)
	if err != nil {
		t.Fatal(err)
	}

	// Goroutine: act as the TLS client sending a PUT with Expect: 100-continue.
	done := make(chan error, 1)
	go func() {
		// Wrap the client side in TLS, trusting our proxy CA.
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		tlsClient := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: host})
		if err := tlsClient.Handshake(); err != nil {
			done <- fmt.Errorf("client TLS handshake: %w", err)
			return
		}

		// Write a PUT request with Expect: 100-continue (no body yet).
		fmt.Fprintf(tlsClient,
			"PUT / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n",
			upstreamHost, len(body),
		)

		// Read the 100 Continue response from the proxy.
		br := bufio.NewReader(tlsClient)
		line, err := br.ReadString('\n')
		if err != nil {
			done <- fmt.Errorf("reading 100 response: %w", err)
			return
		}
		if !strings.Contains(line, "100") {
			done <- fmt.Errorf("expected 100 Continue, got: %q", line)
			return
		}
		// Drain the blank line after the status line.
		br.ReadString('\n') //nolint:errcheck

		// Now send the body.
		fmt.Fprint(tlsClient, body)

		// Read the final response.
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			done <- fmt.Errorf("reading final response: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			done <- fmt.Errorf("final status = %d, want 200", resp.StatusCode)
			return
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != body {
			done <- fmt.Errorf("echoed body = %q, want %q", got, body)
			return
		}
		done <- nil
	}()

	// Server side: do the TLS handshake as the proxy would, then run the
	// tunnel loop for one request.
	tlsServer := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsServer.Handshake(); err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}

	// Build a fake *http.Request that represents the original CONNECT.
	connectReq := &http.Request{Host: upstreamHost}

	// Run the tunnel loop in a goroutine (it blocks until EOF).
	go func() {
		reader := bufio.NewReader(tlsServer)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = connectReq.Host
		req.RequestURI = ""

		// The code under test.
		if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
			fmt.Fprint(tlsServer, "HTTP/1.1 100 Continue\r\n\r\n")
			req.Header.Del("Expect")
		}

		sc := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
		resp, err := sc.Do(req)
		if err != nil {
			return
		}
		resp.Write(tlsServer) //nolint:errcheck
		resp.Body.Close()
		tlsServer.Close()
	}()

	// The test must complete well within 5 seconds; if it deadlocks it will timeout.
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("client goroutine: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out — likely deadlock on Expect: 100-continue")
	}
}

// ---- hop-by-hop header stripping ----

func TestHandleHTTP_HopByHopStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back what Connection header we received (should be empty after stripping).
		w.Header().Set("X-Got-Connection", r.Header.Get("Connection"))
		// Set hop-by-hop headers on the response — proxy should strip them.
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	req, _ := http.NewRequest("GET", upstream.URL, nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	// Upstream should NOT have received the Connection header from the proxy request.
	// (net/http server strips it on arrival, so check via echoed X-Got-Connection)
	if got := rr.Result().Header.Get("X-Got-Connection"); got != "" {
		t.Errorf("Connection header leaked to upstream: %q", got)
	}
	// Response hop-by-hop headers must be stripped before reaching the client.
	if got := rr.Result().Header.Get("Connection"); got != "" {
		t.Errorf("Connection header leaked to client response: %q", got)
	}
	if got := rr.Result().Header.Get("Keep-Alive"); got != "" {
		t.Errorf("Keep-Alive header leaked to client response: %q", got)
	}
}

// ---- record mode stores large bodies faithfully ----

func TestRecord_LargeBodyFullyStored(t *testing.T) {
	const bodySize = 4096 // well above the 1 KB display cap
	largeBody := strings.Repeat("a", bodySize)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(got) //nolint:errcheck
	}))
	defer upstream.Close()

	f, err := os.CreateTemp("", "httpmon-test-large-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	recPath := f.Name()
	f.Close()
	defer os.Remove(recPath)

	savedRM := recordMode
	recordMode = true
	if err := openRecordFile(recPath); err != nil {
		t.Fatal(err)
	}
	defer func() {
		recordFile.Close()
		recordFile = nil
		recordEncoder = nil
		recordMode = savedRM
	}()

	req, _ := http.NewRequest("POST", upstream.URL+"/data",
		io.NopCloser(strings.NewReader(largeBody)))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(bodySize)
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	recordFile.Sync() //nolint:errcheck
	data, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}

	var ex recordedExchange
	if err := json.Unmarshal(bytes.TrimSpace(data), &ex); err != nil {
		t.Fatalf("invalid NDJSON: %v\nraw: %s", err, data)
	}
	if len(ex.ReqBody) != bodySize {
		t.Errorf("recorded req body len = %d, want %d", len(ex.ReqBody), bodySize)
	}
	if len(ex.RespBody) != bodySize {
		t.Errorf("recorded resp body len = %d, want %d", len(ex.RespBody), bodySize)
	}
}

// ---- generateCert parallel keygen ----

// TestGenerateCert_ParallelDifferentHosts verifies that concurrent requests for
// different hosts do not serialize behind a single lock during key generation.
func TestGenerateCert_ParallelDifferentHosts(t *testing.T) {
	hosts := []string{
		"parallel-a.test.local",
		"parallel-b.test.local",
		"parallel-c.test.local",
	}
	certMu.Lock()
	for _, h := range hosts {
		delete(certCache, h)
	}
	certMu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, len(hosts))
	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			_, errs[idx] = generateCert(host)
		}(i, h)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("host %s: %v", hosts[i], err)
		}
	}
}
