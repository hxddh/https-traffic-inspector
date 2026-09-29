package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newH2TLSServer starts a TLS test server that negotiates HTTP/2.
func newH2TLSServer(h http.Handler) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.StartTLS()
	return s
}

// h2ProxiedClient is a client that goes through httpmon and will use HTTP/2
// whenever httpmon offers it.
func h2ProxiedClient(t *testing.T) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + startTestProxy(t))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

func useInsecureUpstream(t *testing.T) {
	t.Helper()
	saved := upstreamClient
	upstreamClient = newUpstreamClient(true)
	t.Cleanup(func() { upstreamClient = saved })
}

// Regression: the MITM listener offered no ALPN and the upstream transport had
// HTTP/2 disabled, so every exchange was silently downgraded to HTTP/1.1.
func TestHTTP2_NegotiatedOnBothSides(t *testing.T) {
	upstreamProto := make(chan int, 1)
	upstream := newH2TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProto <- r.ProtoMajor
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer upstream.Close()
	useInsecureUpstream(t)

	resp, err := h2ProxiedClient(t).Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()              //nolint:errcheck

	if resp.ProtoMajor != 2 {
		t.Errorf("client got %s from httpmon, want HTTP/2", resp.Proto)
	}
	if got := <-upstreamProto; got != 2 {
		t.Errorf("upstream saw HTTP/%d, want HTTP/2", got)
	}
}

// grpcFrame wraps payload in gRPC's length-prefixed message framing.
func grpcFrame(payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}

// A gRPC call needs HTTP/2 end to end, TE: trailers passed upstream, and the
// response trailers carried back: grpc-status lives there. Before 1.4.0 none
// of the three held and gRPC did not work through httpmon at all.
func TestGRPC_UnaryCallThroughTunnel(t *testing.T) {
	upstream := newH2TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "gRPC requires HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
		if r.Header.Get("TE") != "trailers" {
			http.Error(w, "missing TE: trailers", http.StatusBadRequest)
			return
		}
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.Write(grpcFrame([]byte("reply-bytes"))) //nolint:errcheck
		w.Header().Set("Grpc-Status", "5")
		w.Header().Set("Grpc-Message", "user%20not%20found")
	}))
	defer upstream.Close()
	useInsecureUpstream(t)

	out := &syncBuffer{}
	savedOut := textOut
	textOut = out
	defer func() { textOut = savedOut }()

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/users.Users/Get",
		bytes.NewReader(grpcFrame([]byte("request"))))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := h2ProxiedClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, grpcFrame([]byte("reply-bytes"))) {
		t.Errorf("body = %q", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "5" {
		t.Errorf("grpc-status trailer = %q, want 5; trailers = %v", got, resp.Trailer)
	}

	// The body completes on the proxy side just after the client sees it.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "gRPC status") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	text := out.String()
	for _, want := range []string{
		"POST https://", "HTTP/2.0",
		"[gRPC: 1 message, 11 payload bytes]",
		"Trailers:", "gRPC status: 5 NOT_FOUND — user not found",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
}

// An insecure gRPC client reaches its server through a proxy by opening a
// CONNECT tunnel and speaking cleartext HTTP/2 with prior knowledge inside it.
// httpmon used to insist on a TLS handshake there and dropped the connection.
func TestH2C_PriorKnowledgeInsideTunnel(t *testing.T) {
	upstreamProto := make(chan int, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProto <- r.ProtoMajor
		io.WriteString(w, "h2c-ok") //nolint:errcheck
	}))
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	upstream.Config.Protocols = p
	upstream.Start()
	defer upstream.Close()
	target := strings.TrimPrefix(upstream.URL, "http://")

	proxyAddr := startTestProxy(t)
	cp := new(http.Protocols)
	cp.SetUnencryptedHTTP2(true)
	tr := &http.Transport{
		Protocols: cp,
		// Tunnel by hand, as grpc-go does: CONNECT, then HTTP/2 in the clear.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err != nil || resp.StatusCode != http.StatusOK {
				c.Close() //nolint:errcheck
				return nil, fmt.Errorf("CONNECT: %v %v", resp, err)
			}
			return c, nil
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Timeout: 10 * time.Second, Transport: tr}).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("h2c request through the tunnel failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if string(body) != "h2c-ok" || resp.ProtoMajor != 2 {
		t.Errorf("got %s %q, want HTTP/2 \"h2c-ok\"", resp.Proto, body)
	}
	if got := <-upstreamProto; got != 2 {
		t.Errorf("upstream saw HTTP/%d, want HTTP/2", got)
	}
}

// Plaintext ws:// used to go through the ordinary request path, which cannot
// complete a 101 upgrade.
func TestWebSocket_PlaintextThroughProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	target := strings.TrimPrefix(upstream.URL, "http://")

	conn, err := net.DialTimeout("tcp", startTestProxy(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	fmt.Fprintf(conn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	io.WriteString(conn, "ping") //nolint:errcheck
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q, %v", echo, err)
	}
}

func TestRemoveHopByHop_KeepsTETrailers(t *testing.T) {
	h := http.Header{"Te": {"trailers, deflate"}, "Connection": {"keep-alive"}}
	removeHopByHopHeaders(h)
	if got := h.Get("TE"); got != "trailers" {
		t.Errorf("TE = %q, want \"trailers\"", got)
	}
	h = http.Header{"Te": {"gzip"}}
	removeHopByHopHeaders(h)
	if _, ok := h["Te"]; ok {
		t.Errorf("TE: gzip should be stripped, got %v", h)
	}
}

func TestGRPCSummary(t *testing.T) {
	two := append(grpcFrame([]byte("abc")), grpcFrame([]byte("de"))...)
	for _, tc := range []struct {
		raw        []byte
		incomplete bool
		want       string
	}{
		{grpcFrame([]byte("abc")), false, "[gRPC: 1 message, 3 payload bytes]"},
		{two, false, "[gRPC: 2 messages, 5 payload bytes]"},
		{two[:9], false, "[gRPC: 1+ messages, 3+ payload bytes]"},  // cut inside the second header
		{two[:14], false, "[gRPC: 2+ messages, 5+ payload bytes]"}, // cut inside the second payload
		{grpcFrame([]byte("abc")), true, "[gRPC: 1+ messages, 3+ payload bytes]"},
		{append([]byte{1, 0, 0, 0, 1}, 'x'), false, "[gRPC: 1 message, 1 payload bytes, 1 compressed]"},
	} {
		if got := grpcSummary(tc.raw, tc.incomplete); got != tc.want {
			t.Errorf("grpcSummary(%v, %v) = %q, want %q", tc.raw, tc.incomplete, got, tc.want)
		}
	}
}

func TestGRPCStatusLine(t *testing.T) {
	grpcHdr := http.Header{"Content-Type": {"application/grpc+proto"}}
	if got := grpcStatusLine(grpcHdr, http.Header{"Grpc-Status": {"0"}}); got != "gRPC status: 0 OK" {
		t.Errorf("got %q", got)
	}
	// Trailers-only: an error without a body puts its status in the headers.
	only := http.Header{"Content-Type": {"application/grpc"}, "Grpc-Status": {"16"}, "Grpc-Message": {"bad%20token"}}
	if got := grpcStatusLine(only, nil); got != "gRPC status: 16 UNAUTHENTICATED — bad token" {
		t.Errorf("got %q", got)
	}
	if got := grpcStatusLine(http.Header{"Content-Type": {"application/json"}}, nil); got != "" {
		t.Errorf("non-gRPC got %q", got)
	}
}

// Regression: over HTTP/2 an empty body is not http.NoBody, so the v1.2.2
// fix did not apply and a "content-length: 0" POST from curl --http2 reached
// the upstream as Transfer-Encoding: chunked again.
func TestForward_ZeroLengthBodyKeepsContentLengthFraming(t *testing.T) {
	type framing struct {
		te []string
		cl int64
	}
	seen := make(chan framing, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- framing{te: r.TransferEncoding, cl: r.ContentLength}
	}))
	defer upstream.Close()

	// What the HTTP/2 server hands a handler for curl -X POST -d "" --http2.
	req := httptest.NewRequest(http.MethodPost, upstream.URL+"/empty", nil)
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
	req.Body = io.NopCloser(strings.NewReader(""))
	req.ContentLength = 0
	req.RequestURI = ""

	forwardRequest(httptest.NewRecorder(), req, upstreamClient)

	got := <-seen
	if len(got.te) != 0 || got.cl != 0 {
		t.Errorf("upstream saw Transfer-Encoding %v, ContentLength %d; want Content-Length: 0", got.te, got.cl)
	}
}
