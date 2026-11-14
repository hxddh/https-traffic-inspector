package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingProxy is a minimal upstream proxy: it tunnels CONNECT and answers
// plain proxied requests itself, counting both.
type countingProxy struct {
	addr     string
	connects atomic.Int32
	plain    atomic.Int32
}

func startCountingProxy(t *testing.T) *countingProxy {
	t.Helper()
	cp := &countingProxy{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			cp.plain.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "via-proxy") //nolint:errcheck
			return
		}
		cp.connects.Add(1)
		up, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close() //nolint:errcheck
			return
		}
		io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n") //nolint:errcheck
		go func() { io.Copy(up, client); up.Close() }()                       //nolint:errcheck
		go func() { io.Copy(client, up); client.Close() }()                   //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	cp.addr = strings.TrimPrefix(srv.URL, "http://")
	return cp
}

func useUpstreamProxy(t *testing.T, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	saved := upstreamProxy
	upstreamProxy = u
	t.Cleanup(func() { upstreamProxy = saved })
}

// Regression: replay built its own transport with no proxy, so --upstream-proxy
// and HTTPS_PROXY were ignored and replay failed behind an egress proxy.
func TestReplay_UsesUpstreamProxy(t *testing.T) {
	cp := startCountingProxy(t)
	useUpstreamProxy(t, "http://"+cp.addr)

	// The target is never contacted directly: the proxy answers for it.
	path := writeRecording(t, recordedExchange{
		ID: 1, Method: "GET", URL: "http://upstream.invalid/thing",
		Status: 200, StatusText: "200 OK", RespBody: "via-proxy",
	})
	if code := replayFile(path, "", 0, true); code != 0 {
		t.Errorf("code = %d, want 0: replay should have gone through the upstream proxy", code)
	}
	if got := cp.plain.Load(); got != 1 {
		t.Errorf("upstream proxy saw %d requests, want 1", got)
	}
}

func TestReplay_UnreachableUpstreamProxyFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close() //nolint:errcheck
	useUpstreamProxy(t, "http://"+dead)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "direct") //nolint:errcheck
	}))
	defer target.Close()

	path := writeRecording(t, recordedExchange{
		ID: 1, Method: "GET", URL: target.URL + "/thing",
		Status: 200, StatusText: "200 OK", RespBody: "direct",
	})
	if code := replayFile(path, "", 0, true); code != 2 {
		t.Errorf("code = %d, want 2: replay reached the target directly despite --upstream-proxy", code)
	}
}

// Regression: the WebSocket splice dialled the upstream with tls.Dial, going
// around --upstream-proxy and HTTPS_PROXY.
func TestWebSocket_TunnelsThroughUpstreamProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n") //nolint:errcheck
		rw.Flush()                                                                                              //nolint:errcheck
		io.Copy(conn, rw)                                                                                       //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")

	cp := startCountingProxy(t)
	useUpstreamProxy(t, "http://"+cp.addr)
	savedInsecure := insecureUpstream
	insecureUpstream = true
	defer func() { insecureUpstream = savedInsecure }()

	conn, err := net.DialTimeout("tcp", startTestProxy(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT to httpmon: %v %v", resp, err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	host, _, _ := net.SplitHostPort(upstreamHost)
	tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host})
	fmt.Fprintf(tc, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", upstreamHost)
	tbr := bufio.NewReader(tc)
	resp, err = http.ReadResponse(tbr, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	io.WriteString(tc, "ping") //nolint:errcheck
	echo := make([]byte, 4)
	if _, err := io.ReadFull(tbr, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q, %v", echo, err)
	}
	if got := cp.connects.Load(); got != 1 {
		t.Errorf("upstream proxy saw %d CONNECTs, want 1: the splice went around it", got)
	}
}
