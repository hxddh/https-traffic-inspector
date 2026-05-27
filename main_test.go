package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
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
