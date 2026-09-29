package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---- forwarding ----

// inflight counts exchanges still being relayed. The wrapped command can see
// the last byte of a response before httpmon has read the upstream's
// end-of-stream -- with an HTTP/2 upstream they arrive separately -- so
// when the command exits, its final exchange may not be logged, recorded or
// added to the HAR yet.
var inflight atomic.Int64

// drainInflight waits, up to max, for in-flight exchanges to finish.
func drainInflight(max time.Duration) {
	deadline := time.Now().Add(max)
	for inflight.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// forwardRequest sends req upstream through client and relays the response to
// w. Every proxied request takes this path, whether it arrived as a plain
// proxy request or inside a CONNECT tunnel, over HTTP/1.1 or HTTP/2.
// req.URL must already be absolute.
func forwardRequest(w http.ResponseWriter, req *http.Request, client *http.Client) {
	inflight.Add(1)
	defer inflight.Add(-1)

	// A body known to be empty must reach the transport as http.NoBody, or it
	// reads as "length unknown" and goes upstream as Transfer-Encoding:
	// chunked, which S3 and others reject. HTTP/1.1 servers already hand one
	// over; the HTTP/2 server does not.
	if req.ContentLength == 0 && req.Body != nil && req.Body != http.NoBody {
		req.Body.Close() //nolint:errcheck
		req.Body = http.NoBody
	}

	shouldLog := matchesFilter(req)
	var reqID int
	if shouldLog {
		reqID = logRequest(req)
	}

	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		if shouldLog {
			discardReqID(reqID)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyReq.Header = req.Header.Clone()
	proxyReq.ContentLength = req.ContentLength
	// The server in front of this handler has already answered any
	// Expect: 100-continue; asking the upstream again only adds a round trip.
	proxyReq.Header.Del("Expect")
	removeHopByHopHeaders(proxyReq.Header)

	resp, err := client.Do(proxyReq)
	if err != nil {
		if shouldLog {
			discardReqID(reqID)
		}
		if !tuiMode && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "httpmon: upstream request to %s failed: %v\n", req.URL.Host, err)
		}
		warnTLSVerification(req.URL.Hostname(), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if shouldLog {
		logResponse(resp, reqID)
	}
	// Close whatever resp.Body is by now: logResponse wraps it in a sampler,
	// and a deferred resp.Body.Close() bound earlier would close the original
	// underneath it. The sampler would then never report, and an exchange
	// whose copy stopped short of EOF was never logged or recorded at all.
	defer func() { resp.Body.Close() }() //nolint:errcheck

	h := w.Header()
	for k, v := range resp.Header {
		h[k] = v
	}
	removeHopByHopHeaders(h)
	w.WriteHeader(resp.StatusCode)

	// Flush as the body is written: buffering here would hold a streaming
	// response until the stream ended.
	fl, _ := w.(http.Flusher)
	copyFlushing(w, resp.Body, fl) //nolint:errcheck

	// Trailers are known only once the body has been read. gRPC carries its
	// status in them, so dropping them breaks every call.
	for k, vv := range resp.Trailer {
		h[http.TrailerPrefix+k] = vv
	}
}

// handleHTTP serves a plain (absolute-form) proxy request.
func handleHTTP(w http.ResponseWriter, req *http.Request) {
	u := *req.URL
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Host == "" {
		u.Host = req.Host
	}
	req.URL = &u

	if isWebSocketUpgrade(req) {
		handleWebSocket(w, req, false)
		return
	}
	forwardRequest(w, req, upstreamClient)
}

// ---- WebSocket ----

func isWebSocketUpgrade(req *http.Request) bool {
	return req.ProtoMajor == 1 && strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

// handleWebSocket completes an upgrade handshake with the upstream and then
// splices the two connections. An upgraded connection is no longer HTTP, so it
// cannot go through the shared transport.
func handleWebSocket(w http.ResponseWriter, req *http.Request, useTLS bool) {
	shouldLog := matchesFilter(req)
	var reqID int
	if shouldLog {
		reqID = logRequest(req)
		defer discardReqID(reqID)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket upgrade requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}

	port := "80"
	if useTLS {
		port = "443"
	}
	hostport := hostPortDefault(req.URL, port)
	upConn, err := dialUpstream(hostport, req.URL.Hostname(), useTLS)
	if err != nil {
		warnTLSVerification(req.URL.Hostname(), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upConn.Close()

	clientConn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	spliceWebSocket(upConn, req, clientConn, rw.Writer, rw.Reader)
}

// ---- CONNECT tunnels ----

// handleConnect terminates a CONNECT tunnel and serves whatever the client
// speaks inside it: TLS (HTTP/1.1 or HTTP/2, chosen by ALPN) or cleartext
// (HTTP/1.1, or HTTP/2 with prior knowledge, which is how an insecure gRPC
// client talks through a proxy).
func handleConnect(w http.ResponseWriter, r *http.Request) {
	if !jsonMode && !tuiMode {
		emitText(fmt.Sprintf("\n\033[33m=== CONNECT %s ===\033[0m\n\n", r.Host))
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	// Check hijacking support before sending 200 so we can still return a proper HTTP error.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hijack error for %s: %v\n", host, err)
		return
	}

	// Write the tunnel response directly rather than through ResponseWriter.
	// net/http would add Date and Transfer-Encoding: chunked, which RFC 9110
	// §9.3.6 forbids on a 2xx CONNECT response: the client then waits for a
	// terminating chunk that never arrives and the command hangs.
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		clientConn.Close() //nolint:errcheck
		return
	}

	// The first byte tells TLS (a handshake record) from cleartext. A client
	// that sends nothing is waiting for the server to speak first (SMTP, SSH,
	// MySQL…): that is not HTTP, so the tunnel is relayed untouched.
	br := bufio.NewReader(clientConn)
	conn := &bufferedConn{Conn: clientConn, r: br}
	clientConn.SetReadDeadline(time.Now().Add(clientFirstByteWait)) //nolint:errcheck
	first, err := br.Peek(1)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			clientConn.SetReadDeadline(time.Time{}) //nolint:errcheck
			relayOpaque(conn, r.Host, host)
			return
		}
		clientConn.Close() //nolint:errcheck
		return
	}

	if first[0] != tlsHandshakeRecord {
		clientConn.SetReadDeadline(time.Time{}) //nolint:errcheck
		if !looksLikeHTTP(first[0]) {
			relayOpaque(conn, r.Host, host)
			return
		}
		plainTunnels.serve(conn, r.Host)
		return
	}
	clientConn.SetReadDeadline(time.Now().Add(tunnelSetupTimeout)) //nolint:errcheck

	cert, err := generateCert(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: certificate for %s: %v\n", host, err)
		clientConn.Close() //nolint:errcheck
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake error for %s: %v\n", host, err)
		clientConn.Close() //nolint:errcheck
		return
	}
	clientConn.SetReadDeadline(time.Time{}) //nolint:errcheck
	tlsTunnels.serve(tlsConn, r.Host)
}

const (
	tlsHandshakeRecord = 0x16
	tunnelSetupTimeout = 30 * time.Second
	// clientFirstByteWait is how long a tunnel may stay silent before it is
	// taken to carry a server-first protocol. TLS and HTTP clients speak
	// immediately after the CONNECT response.
	clientFirstByteWait = time.Second
)

// looksLikeHTTP reports whether a cleartext tunnel opens like HTTP: a method
// token (GET, POST…) or the HTTP/2 preface "PRI", all uppercase ASCII.
func looksLikeHTTP(first byte) bool {
	return first >= 'A' && first <= 'Z'
}

// relayOpaque splices a tunnel that does not carry HTTP straight to its
// target. Breaking it would break the wrapped command for traffic httpmon
// cannot show anyway.
func relayOpaque(client net.Conn, target, host string) {
	if !jsonMode && !tuiMode {
		emitText(fmt.Sprintf("\033[33m    %s: not HTTP, relayed without inspection\033[0m\n\n", target))
	}
	up, err := dialUpstream(target, host, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: tunnel to %s failed: %v\n", target, err)
		client.Close() //nolint:errcheck
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); closeWrite(up); done <- struct{}{} }()     //nolint:errcheck
	go func() { io.Copy(client, up); closeWrite(client); done <- struct{}{} }() //nolint:errcheck
	<-done
	<-done
	up.Close()     //nolint:errcheck
	client.Close() //nolint:errcheck
}

// closeWrite half-closes c when it supports it, so each direction of a
// relay can finish independently; otherwise it closes c entirely.
func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if bc, ok := c.(*bufferedConn); ok {
		c = bc.Conn
	}
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite() //nolint:errcheck
		return
	}
	c.Close() //nolint:errcheck
}

// bufferedConn is a net.Conn whose reads first drain the bytes peeked to
// classify the tunnel.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// tunnelServer serves the connections handed to it from CONNECT tunnels with
// a standard http.Server, which brings HTTP/2, Expect: 100-continue, keep-alive
// and response framing with it.
type tunnelServer struct {
	once    sync.Once
	h2c     bool // cleartext: accept HTTP/2 with prior knowledge
	ln      *connListener
	targets sync.Map // net.Conn -> CONNECT target (host:port)
}

var (
	tlsTunnels   = &tunnelServer{}
	plainTunnels = &tunnelServer{h2c: true}
)

type tunnelTargetKey struct{}

func (t *tunnelServer) serve(c net.Conn, target string) {
	t.once.Do(t.start)
	t.targets.Store(c, target)
	t.ln.push(c)
}

func (t *tunnelServer) start() {
	t.ln = newConnListener()
	srv := &http.Server{
		Handler: http.HandlerFunc(handleTunnelRequest),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if target, ok := t.targets.Load(c); ok {
				return context.WithValue(ctx, tunnelTargetKey{}, target)
			}
			return ctx
		},
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				t.targets.Delete(c)
			}
		},
		ReadHeaderTimeout: 30 * time.Second,
		// Per-connection errors (a client hanging up mid-request) are routine
		// here and would only clutter the captured output.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	if t.h2c {
		p := new(http.Protocols)
		p.SetHTTP1(true)
		p.SetUnencryptedHTTP2(true)
		srv.Protocols = p
	}
	go srv.Serve(t.ln) //nolint:errcheck
}

// handleTunnelRequest serves one request received inside a CONNECT tunnel.
func handleTunnelRequest(w http.ResponseWriter, r *http.Request) {
	target, _ := r.Context().Value(tunnelTargetKey{}).(string)
	u := *r.URL
	u.Scheme = "http"
	if r.TLS != nil {
		u.Scheme = "https"
	}
	u.Host = target
	r.URL = &u

	if isWebSocketUpgrade(r) {
		handleWebSocket(w, r, r.TLS != nil)
		return
	}

	client := upstreamClient
	if r.ProtoMajor == 2 && r.TLS == nil {
		// The client spoke cleartext HTTP/2, so the upstream expects it too:
		// an insecure gRPC server does not speak HTTP/1.1 at all.
		client = h2cClient
	}
	forwardRequest(w, r, client)
}

// connListener is a net.Listener fed by hand, so an http.Server can serve
// connections that were accepted elsewhere.
type connListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnListener() *connListener {
	return &connListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		c.Close() //nolint:errcheck
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr { return tunnelAddr{} }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "tunnel" }
func (tunnelAddr) String() string  { return "connect-tunnel" }

// ---- upstream dialing for spliced connections ----

// dialUpstream opens a raw connection to hostport for a WebSocket splice,
// through the upstream proxy when one applies.
func dialUpstream(hostport, serverName string, useTLS bool) (net.Conn, error) {
	if useTLS {
		return dialUpstreamTLS(hostport, serverName)
	}
	d := &net.Dialer{Timeout: upstreamDialTimeout}
	p, err := upstreamProxyFor(&url.URL{Scheme: "http", Host: hostport})
	if err != nil {
		return nil, err
	}
	if p == nil {
		return d.Dial("tcp", hostport)
	}
	return dialProxyTunnel(d, p, hostport)
}
