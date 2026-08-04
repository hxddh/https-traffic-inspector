package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Regression: bodies were read with io.ReadFull up front, which only returns
// once the peek buffer is full or the stream ends. A trickling response was
// therefore withheld in full until the upstream closed it -- measured as SSE
// time-to-first-byte going from 0.02s to 6.02s. Delivery must not wait on
// sampling.
func TestStreaming_ResponseIsNotHeldUntilTheStreamEnds(t *testing.T) {
	const events = 4
	const gap = 250 * time.Millisecond

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("test server ResponseWriter is not a Flusher")
			return
		}
		for i := 0; i < events; i++ {
			fmt.Fprintf(w, "data: event %d\n\n", i)
			fl.Flush()
			time.Sleep(gap)
		}
	}))
	defer upstream.Close()

	savedClient := upstreamClient
	upstreamClient = newUpstreamClient(true)
	defer func() { upstreamClient = savedClient }()

	client, cleanup := proxiedClient(t)
	defer cleanup()

	start := time.Now()
	resp, err := client.Get(upstream.URL + "/sse")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read just the first event and time it.
	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	firstByte := time.Since(start)
	if err != nil && err != io.EOF {
		t.Fatalf("reading first chunk: %v", err)
	}
	if n == 0 {
		t.Fatal("first read returned no data")
	}

	total := time.Duration(events) * gap
	if firstByte > total/2 {
		t.Errorf("first byte arrived after %v; the stream runs for ~%v, so the body was buffered rather than forwarded",
			firstByte.Round(time.Millisecond), total)
	}
}

// The same fault applied to uploads: three small chunks 1.5s apart reached the
// server as one write.
func TestStreaming_RequestIsNotHeldUntilTheUploadEnds(t *testing.T) {
	const gap = 250 * time.Millisecond

	firstChunk := make(chan time.Duration, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		buf := make([]byte, 32)
		n, _ := r.Body.Read(buf)
		if n > 0 {
			select {
			case firstChunk <- time.Since(started):
			default:
			}
		}
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	savedClient := upstreamClient
	upstreamClient = newUpstreamClient(true)
	defer func() { upstreamClient = savedClient }()

	client, cleanup := proxiedClient(t)
	defer cleanup()

	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 4; i++ {
			fmt.Fprintf(pw, "chunk%d\n", i)
			time.Sleep(gap)
		}
		pw.Close() //nolint:errcheck
	}()

	req, err := http.NewRequest("POST", upstream.URL+"/upload", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	resp.Body.Close() //nolint:errcheck

	select {
	case d := <-firstChunk:
		// The upload runs for ~1s; the server must see data well before the end.
		if d > 3*gap {
			t.Errorf("server saw the first chunk only after %v, so the upload was buffered",
				d.Round(time.Millisecond))
		}
	default:
		t.Fatal("server never reported receiving a chunk")
	}
}

// Sampling must not corrupt or drop payload bytes.
func TestStreaming_BodyForwardedIntact(t *testing.T) {
	payload := make([]byte, 300000)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(payload) //nolint:errcheck
	}))
	defer upstream.Close()

	savedClient := upstreamClient
	upstreamClient = newUpstreamClient(true)
	defer func() { upstreamClient = savedClient }()

	client, cleanup := proxiedClient(t)
	defer cleanup()

	resp, err := client.Get(upstream.URL + "/blob")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("payload differs at byte %d", i)
		}
	}
}

// proxiedClient returns an http.Client whose requests go through a live
// httpmon proxy, trusting the ephemeral CA.
func proxiedClient(t *testing.T) (*http.Client, func()) {
	t.Helper()
	proxyAddr := startTestProxy(t)
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}, tr.CloseIdleConnections
}
