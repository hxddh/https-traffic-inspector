package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	upstreamClient *http.Client
	// h2cClient speaks cleartext HTTP/2 upstream, for clients that spoke it
	// to httpmon: an insecure gRPC server accepts nothing else.
	h2cClient *http.Client
)

// newUpstreamClient builds the shared client used for all upstream requests.
// When insecure is true, upstream certificates are not verified.
//
// Requests go through upstreamProxy, falling back to the environment's proxy
// settings. httpmon only injects its own address into the *subprocess*
// environment, so reading the environment here picks up the outer proxy rather
// than looping back into httpmon.
//
// Every upstream path -- proxied requests, replay and WebSocket tunnels --
// resolves its proxy through upstreamProxyFor, so none of them can bypass it.
func newUpstreamClient(insecure bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           func(r *http.Request) (*url.URL, error) { return upstreamProxyFor(r.URL) },
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // opt-in via --insecure-upstream
			// A custom TLS config otherwise turns HTTP/2 off. Without it gRPC
			// cannot work, and every HTTP/2 client is silently downgraded.
			ForceAttemptHTTP2: true,
			// The transport would otherwise add "Accept-Encoding: gzip" to a
			// request that had none and decompress the reply itself: the
			// upstream would see a request the client never sent, and the
			// logged request would not be the one that went out.
			DisableCompression:  true,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newH2CClient builds the client for cleartext HTTP/2 upstreams.
func newH2CClient() *http.Client {
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:              func(r *http.Request) (*url.URL, error) { return upstreamProxyFor(r.URL) },
			Protocols:          p,
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// upstreamProxyFor returns the proxy httpmon's own traffic to u goes through,
// or nil to connect directly: --upstream-proxy when set, else the environment.
func upstreamProxyFor(u *url.URL) (*url.URL, error) {
	if upstreamProxy != nil {
		return upstreamProxy, nil
	}
	return http.ProxyFromEnvironment(&http.Request{URL: u})
}

// upstreamDialTimeout bounds connecting to an upstream or proxy and completing
// the TLS handshake, matching what the upstream transport allows.
const upstreamDialTimeout = 30 * time.Second

// dialUpstreamTLS opens a TLS connection to hostport for a WebSocket splice,
// tunnelling through the upstream proxy when one applies. The splice needs a
// raw connection, which the shared http.Transport cannot hand out, but it must
// follow the same route and verification policy as every other request.
func dialUpstreamTLS(hostport, serverName string) (net.Conn, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: insecureUpstream, //nolint:gosec // opt-in via --insecure-upstream
		ServerName:         serverName,
	}
	d := &net.Dialer{Timeout: upstreamDialTimeout}

	p, err := upstreamProxyFor(&url.URL{Scheme: "https", Host: hostport})
	if err != nil {
		return nil, err
	}
	if p == nil {
		return tls.DialWithDialer(d, "tcp", hostport, cfg)
	}

	raw, err := dialProxyTunnel(d, p, hostport)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	raw.SetDeadline(time.Now().Add(upstreamDialTimeout)) //nolint:errcheck
	if err := tc.Handshake(); err != nil {
		raw.Close() //nolint:errcheck
		return nil, err
	}
	raw.SetDeadline(time.Time{}) //nolint:errcheck
	return tc, nil
}

// dialProxyTunnel connects to proxy p and asks it, with CONNECT, for a tunnel
// to target.
func dialProxyTunnel(d *net.Dialer, p *url.URL, target string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	switch p.Scheme {
	case "http", "":
		conn, err = d.Dial("tcp", hostPortDefault(p, "80"))
	case "https":
		conn, err = tls.DialWithDialer(d, "tcp", hostPortDefault(p, "443"), &tls.Config{ServerName: p.Hostname()})
	default:
		return nil, fmt.Errorf("upstream proxy scheme %q is not supported for WebSocket tunnels", p.Scheme)
	}
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if p.User != nil {
		pass, _ := p.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(p.User.Username() + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}

	conn.SetDeadline(time.Now().Add(upstreamDialTimeout)) //nolint:errcheck
	if err := req.Write(conn); err != nil {
		conn.Close() //nolint:errcheck
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close() //nolint:errcheck
		return nil, err
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		conn.Close() //nolint:errcheck
		return nil, fmt.Errorf("upstream proxy refused CONNECT %s: %s", target, resp.Status)
	}
	// The server speaks first only after our TLS ClientHello, so anything
	// already buffered here would be lost; treat it as a protocol error.
	if br.Buffered() > 0 {
		conn.Close() //nolint:errcheck
		return nil, fmt.Errorf("upstream proxy sent unexpected data after CONNECT %s", target)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck
	return conn, nil
}

func hostPortDefault(u *url.URL, port string) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// isTLSVerificationError reports whether err came from upstream certificate
// verification, so the user can be pointed at --insecure-upstream.
func isTLSVerificationError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidErr)
}

// warnTLSVerification prints an actionable hint when an upstream request fails
// certificate verification.
func warnTLSVerification(host string, err error) {
	if insecureUpstream || !isTLSVerificationError(err) {
		return
	}
	noticef("upstream TLS verification failed for %s; re-run with --insecure-upstream to bypass", host)
}

// bodyAllowedForStatus mirrors net/http's unexported helper of the same name:
// 1xx, 204 and 304 responses carry no body, so they must not be given body
// framing headers.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}
	return true
}

// hopByHopHeaders lists the standard hop-by-hop headers defined in RFC 7230 §6.1.
// Proxy-Connection is not in the RFC but is sent by curl and others to the
// proxy, and must not reach the origin either.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// removeHopByHopHeaders strips hop-by-hop headers from h per RFC 7230 §6.1.
// It also removes any headers named in the Connection header value.
//
// "TE: trailers" survives: it is the one TE value HTTP/2 permits, and gRPC
// servers reject a call without it.
func removeHopByHopHeaders(h http.Header) {
	wantsTrailers := false
	for _, v := range h.Values("TE") {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "trailers") {
				wantsTrailers = true
			}
		}
	}
	defer func() {
		if wantsTrailers {
			h.Set("TE", "trailers")
		}
	}()

	for _, v := range h["Connection"] {
		for _, f := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, hdr := range hopByHopHeaders {
		h.Del(hdr)
	}
}

// writeConnError writes an HTTP error response directly onto a raw connection.
// Used inside a CONNECT tunnel where http.ResponseWriter is no longer available.
func writeConnError(w io.Writer, statusCode int, msg string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader(msg)),
		Header:     make(http.Header),
		Close:      true,
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Write(w) //nolint:errcheck
}
