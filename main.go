package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// certEntry wraps a TLS certificate with an expiry time for cache TTL enforcement.
type certEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

var (
	requestCounter int
	counterMu      sync.Mutex
	proxyPort      string
	caCert         *x509.Certificate
	caKey          *ecdsa.PrivateKey
	certCache      = make(map[string]*certEntry)
	certMu         sync.Mutex
	certTTL        = time.Hour // overridden by --cert-ttl flag
	upstreamClient *http.Client

	// set by flags
	filterPattern    string
	jsonMode         bool
	tuiMode          bool
	recordMode       bool
	harMode          bool
	harPath          string
	insecureUpstream bool
	displayMaxBody   = 1000    // --max-body: bytes of body shown in text/JSON/TUI output
	captureMaxBody   = 1 << 20 // --max-capture: bytes of body kept for --record/--har/decompression

	// per-request start times for duration tracking (used in TUI and text mode)
	reqStartTimes = make(map[int]time.Time)
	reqStartMu    sync.Mutex
)

// version is the released build identifier, injected at link time with
// -ldflags "-X main.version=<tag>".
var version = "dev"

func init() {
	var err error
	caCert, caKey, err = generateCA()
	if err != nil {
		log.Fatal("Failed to generate CA:", err)
	}

	// Verified by default; run() replaces this once --insecure-upstream is parsed.
	upstreamClient = newUpstreamClient(false)
}

// newUpstreamClient builds the shared client used for all upstream requests.
// When insecure is true, upstream certificates are not verified.
func newUpstreamClient(insecure bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // opt-in via --insecure-upstream
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ---- cleanup ----

var (
	cleanups   []func()
	cleanupsMu sync.Mutex
)

// addCleanup registers a function to run before run() returns. An explicit list
// is used instead of defer because run() has several exit points and because it
// lets tests trigger cleanup directly.
func addCleanup(f func()) {
	cleanupsMu.Lock()
	cleanups = append(cleanups, f)
	cleanupsMu.Unlock()
}

// runCleanups executes registered cleanups in reverse registration order.
func runCleanups() {
	cleanupsMu.Lock()
	fs := cleanups
	cleanups = nil
	cleanupsMu.Unlock()
	for i := len(fs) - 1; i >= 0; i-- {
		fs[i]()
	}
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
	fmt.Fprintf(os.Stderr,
		"httpmon: upstream TLS verification failed for %s; re-run with --insecure-upstream to bypass\n",
		host)
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal("Failed to generate serial number:", err)
	}
	return n
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: randSerial(),
		Subject: pkix.Name{
			Organization: []string{"HTTP Monitor CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// generateCert returns a cached or newly-created leaf cert for host.
// Key generation runs outside the mutex so concurrent requests for different
// hosts proceed in parallel. A double-checked store ensures only one cert per
// host ends up in the cache even if two goroutines race on the same host.
func generateCert(host string) (*tls.Certificate, error) {
	// Fast path: return cached cert without generating.
	certMu.Lock()
	if e, ok := certCache[host]; ok && time.Now().Before(e.expiresAt) {
		cert := e.cert
		certMu.Unlock()
		return cert, nil
	}
	certMu.Unlock()

	// Slow path: generate outside the lock so other hosts are not blocked.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: randSerial(),
		Subject: pkix.Name{
			Organization: []string{"HTTP Monitor"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// An IP-literal host needs an IP SAN; a DNS name must not be put in one.
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	if certTTL > 0 {
		certMu.Lock()
		// Re-check: another goroutine may have stored a cert while we were generating.
		if e, ok := certCache[host]; ok && time.Now().Before(e.expiresAt) {
			cert = e.cert
		} else {
			certCache[host] = &certEntry{cert: cert, expiresAt: time.Now().Add(certTTL)}
		}
		certMu.Unlock()
	}

	return cert, nil
}

// startCertJanitor evicts expired cert cache entries every sweepInterval.
func startCertJanitor(sweepInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			certMu.Lock()
			for host, e := range certCache {
				if now.After(e.expiresAt) {
					delete(certCache, host)
				}
			}
			certMu.Unlock()
		}
	}()
}

func nextReqID() int {
	counterMu.Lock()
	defer counterMu.Unlock()
	requestCounter++
	return requestCounter
}

// discardReqID cleans up reqStartTimes and pendingRecords when a request
// cannot be completed and logResponse will never be called for this ID.
func discardReqID(reqID int) {
	reqStartMu.Lock()
	delete(reqStartTimes, reqID)
	reqStartMu.Unlock()
	if recordMode {
		pendingRecordsMu.Lock()
		delete(pendingRecords, reqID)
		pendingRecordsMu.Unlock()
	}
	if harMode {
		pendingHARMu.Lock()
		delete(pendingHAR, reqID)
		pendingHARMu.Unlock()
	}
}

// matchesFilter reports whether the request URL or host contains filterPattern.
// When filterPattern is empty every request matches.
func matchesFilter(req *http.Request) bool {
	if filterPattern == "" {
		return true
	}
	p := strings.ToLower(filterPattern)
	return strings.Contains(strings.ToLower(req.URL.String()), p) ||
		strings.Contains(strings.ToLower(req.Host), p) ||
		strings.Contains(strings.ToLower(req.URL.Path), p)
}

// ---- JSON output types ----

type jsonRequest struct {
	ID      int               `json:"id"`
	Time    string            `json:"time"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Proto   string            `json:"proto"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type jsonResponse struct {
	ReqID   int               `json:"req_id"`
	Status  int               `json:"status"`
	Proto   string            `json:"proto"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

var (
	jsonEnc   = json.NewEncoder(os.Stdout)
	jsonEncMu sync.Mutex
)

func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
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
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// removeHopByHopHeaders strips hop-by-hop headers from h per RFC 7230 §6.1.
// It also removes any headers named in the Connection header value.
func removeHopByHopHeaders(h http.Header) {
	for _, v := range h["Connection"] {
		for _, f := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, hdr := range hopByHopHeaders {
		h.Del(hdr)
	}
}

// ---- logging ----

// logRequest logs the request and returns the assigned request ID.
func logRequest(req *http.Request) int {
	reqID := nextReqID()

	startTime := time.Now()
	reqStartMu.Lock()
	reqStartTimes[reqID] = startTime
	reqStartMu.Unlock()

	bodyView := renderBody(&req.Body, req.Header)

	// Recordings and HAR keep the verbatim capture, without a display marker.
	if recordMode {
		recordRequest(reqID, req, bodyView.Text)
	}
	if harMode {
		addHARRequest(reqID, req, bodyView.Text, startTime)
	}

	bodyStr := truncateForDisplay(bodyView)

	if tuiMode {
		entry := &tuiEntry{
			id:         reqID,
			startTime:  startTime,
			method:     req.Method,
			host:       req.Host,
			path:       req.URL.Path,
			rawURL:     req.URL.String(),
			reqHeaders: flattenHeaders(req.Header),
			reqBody:    bodyStr,
			pending:    true,
		}
		select {
		case tuiCh <- tuiReqMsg{entry}:
		default:
		}
		return reqID
	}

	if jsonMode {
		jsonEncMu.Lock()
		jsonEnc.Encode(jsonRequest{ //nolint:errcheck
			ID:      reqID,
			Time:    time.Now().Format(time.RFC3339),
			Method:  req.Method,
			URL:     req.URL.String(),
			Proto:   req.Proto,
			Host:    req.Host,
			Headers: flattenHeaders(req.Header),
			Body:    bodyStr,
		})
		jsonEncMu.Unlock()
		return reqID
	}

	fmt.Printf("\n\033[36m=== REQUEST #%d ===\033[0m\n", reqID)
	fmt.Printf("Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("%s %s %s\n", req.Method, req.URL.String(), req.Proto)
	fmt.Printf("Host: %s\n", req.Host)

	if strings.Contains(req.Host, ".amazonaws.com") {
		logS3Info(req)
	}

	if req.URL.RawQuery != "" {
		fmt.Println("\nQuery Parameters:")
		params, _ := url.ParseQuery(req.URL.RawQuery)
		for k, v := range params {
			fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
		}
	}

	fmt.Println("\nHeaders:")
	for k, v := range req.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}

	if bodyStr != "" {
		fmt.Printf("\nBody:\n%s\n", bodyStr)
	}
	fmt.Println()
	return reqID
}

func logS3Info(req *http.Request) {
	host := req.Host
	// virtual-hosted style: <bucket>.s3[.<region>].amazonaws.com/<key>
	if idx := strings.Index(host, ".s3."); idx > 0 {
		fmt.Printf("\033[93mS3 Bucket: %s\033[0m\n", host[:idx])
		if key := strings.TrimPrefix(req.URL.Path, "/"); key != "" {
			fmt.Printf("\033[93mS3 Key/Prefix: %s\033[0m\n", key)
		}
		return
	}
	// path-style: s3[.<region>].amazonaws.com/<bucket>/<key>
	pathParts := strings.SplitN(req.URL.Path, "/", 3)
	if len(pathParts) >= 2 && pathParts[1] != "" {
		fmt.Printf("\033[93mS3 Bucket: %s\033[0m\n", pathParts[1])
		if len(pathParts) > 2 && pathParts[2] != "" {
			fmt.Printf("\033[93mS3 Key/Prefix: %s\033[0m\n", pathParts[2])
		}
	}
}

func logResponse(resp *http.Response, reqID int) {
	reqStartMu.Lock()
	start := reqStartTimes[reqID]
	delete(reqStartTimes, reqID)
	reqStartMu.Unlock()
	var dur time.Duration
	if !start.IsZero() {
		dur = time.Since(start)
	}

	bodyView := renderBody(&resp.Body, resp.Header)

	if recordMode {
		recordResponse(reqID, resp, bodyView.Text, dur)
	}
	if harMode {
		addHARResponse(reqID, resp, bodyView.Text, dur)
	}

	bodyStr := truncateForDisplay(bodyView)

	if tuiMode {
		select {
		case tuiCh <- tuiRespMsg{
			reqID:      reqID,
			status:     resp.StatusCode,
			statusText: resp.Status,
			headers:    flattenHeaders(resp.Header),
			body:       bodyStr,
			duration:   dur,
		}:
		default:
		}
		return
	}

	if jsonMode {
		jsonEncMu.Lock()
		jsonEnc.Encode(jsonResponse{ //nolint:errcheck
			ReqID:   reqID,
			Status:  resp.StatusCode,
			Proto:   resp.Proto,
			Headers: flattenHeaders(resp.Header),
			Body:    bodyStr,
		})
		jsonEncMu.Unlock()
		return
	}

	fmt.Printf("\n\033[32m=== RESPONSE ===\033[0m\n")
	fmt.Printf("%s %s\n", resp.Proto, resp.Status)

	fmt.Println("\nHeaders:")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}

	if bodyStr != "" {
		fmt.Printf("\nBody:\n%s\n", bodyStr)
	}
	fmt.Println("\n" + strings.Repeat("-", 60))
}

// truncationMarker is appended whenever displayed content is incomplete, so a
// cut-off body is never mistaken for the whole thing.
const truncationMarker = "\n… [truncated]"

// bodyView is a captured body together with whether more data existed past the
// capture limit. Text carries no truncation marker so that recordings and HAR
// entries stay verbatim; the marker is added only when rendering for display.
type bodyView struct {
	Text      string
	Truncated bool
}

// renderBody peeks at *bodyp and returns a printable representation, decoding
// Content-Encoding when possible. The result may be up to captureMaxBody long;
// callers apply truncateForDisplay before showing it.
func renderBody(bodyp *io.ReadCloser, h http.Header) bodyView {
	if bodyp == nil || *bodyp == nil {
		return bodyView{}
	}

	enc := h.Get("Content-Encoding")
	compressed := len(splitEncodings(enc)) > 0

	peekN := displayMaxBody
	if recordMode || harMode || compressed {
		peekN = captureMaxBody
	}

	// Peek one byte past the limit so a body that exactly fills it can be told
	// apart from one that overflows it. Without this, a body cut off at exactly
	// peekN looks complete and is shown unmarked.
	body := peekBody(bodyp, peekN+1)
	overflow := len(body) > peekN
	if overflow {
		body = body[:peekN]
	}
	if len(body) == 0 {
		return bodyView{}
	}

	if isPrintable(h) {
		return bodyView{Text: string(body), Truncated: overflow}
	}
	if compressed {
		res, err := decompressBody(enc, body)
		if err == nil && isPrintableContentType(h.Get("Content-Type")) {
			return bodyView{Text: string(res.Data), Truncated: res.Truncated || overflow}
		}
		return bodyView{Text: fmt.Sprintf("[%s, %d+ bytes]", enc, len(body))}
	}
	return bodyView{Text: fmt.Sprintf("[binary data, %d+ bytes]", len(body))}
}

// truncateForDisplay caps v at displayMaxBody bytes, backing off to a rune
// boundary so multi-byte characters are never split. Content cut here, or
// already cut at capture time, is marked so it is never read as complete.
func truncateForDisplay(v bodyView) string {
	s := v.Text
	if len(s) > displayMaxBody {
		cut := displayMaxBody
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut] + truncationMarker
	}
	if v.Truncated {
		return s + truncationMarker
	}
	return s
}

// peekBody reads up to n bytes from *body for logging, then reconstructs *body
// with a MultiReader so the full stream (including peeked bytes) can still be forwarded.
func peekBody(body *io.ReadCloser, n int) []byte {
	buf := make([]byte, n)
	nr, _ := io.ReadFull(*body, buf)
	buf = buf[:nr]
	*body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), *body))
	return buf
}

// isPrintableContentType returns true when the MIME type suggests human-readable text.
func isPrintableContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if ct == "" {
		return true
	}
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "html") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "form")
}

// isPrintable returns true when the Content-Type suggests human-readable text
// AND the Content-Encoding is not a compression scheme.
func isPrintable(header http.Header) bool {
	if len(splitEncodings(header.Get("Content-Encoding"))) > 0 {
		return false
	}
	return isPrintableContentType(header.Get("Content-Type"))
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

// systemCABundle returns the path of the OS trusted CA bundle, or "" if not found.
var systemCAPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",     // Debian / Ubuntu / Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",       // RHEL / CentOS / Fedora
	"/etc/ssl/cert.pem",                      // macOS / OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
	"/etc/ssl/ca-bundle.pem",                 // openSUSE
}

func systemCABundle() string {
	for _, p := range systemCAPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// buildCABundle writes a PEM file that contains the system CAs (if found) followed
// by the proxy CA, so the subprocess can verify both proxied and direct TLS connections.
func buildCABundle(proxyCAPEM []byte) (string, error) {
	f, err := os.CreateTemp("", "httpmon-ca-*.crt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if sysCA := systemCABundle(); sysCA != "" {
		data, err := os.ReadFile(sysCA)
		if err == nil {
			f.Write(data) //nolint:errcheck
		}
	}

	if _, err := f.Write(proxyCAPEM); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	if !matchesFilter(req) {
		// Proxy transparently without logging.
		targetURL := *req.URL
		if targetURL.Scheme == "" {
			targetURL.Scheme = "http"
		}
		if targetURL.Host == "" {
			targetURL.Host = req.Host
		}
		proxyReq, err := http.NewRequest(req.Method, targetURL.String(), req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		proxyReq.Header = req.Header.Clone()
		proxyReq.ContentLength = req.ContentLength
		removeHopByHopHeaders(proxyReq.Header)
		resp, err := upstreamClient.Do(proxyReq)
		if err != nil {
			warnTLSVerification(req.Host, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
		return
	}

	reqID := logRequest(req)

	// Copy URL struct to avoid mutating req.URL in place.
	targetURL := *req.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = req.Host
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL.String(), req.Body)
	if err != nil {
		discardReqID(reqID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyReq.Header = req.Header.Clone()
	proxyReq.ContentLength = req.ContentLength
	removeHopByHopHeaders(proxyReq.Header)

	resp, err := upstreamClient.Do(proxyReq)
	if err != nil {
		discardReqID(reqID)
		warnTLSVerification(req.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logResponse(resp, reqID)

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if !jsonMode && !tuiMode {
		fmt.Printf("\n\033[33m=== CONNECT %s ===\033[0m\n\n", r.Host)
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	cert, err := generateCert(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	defer clientConn.Close()

	// Write the tunnel response directly rather than through ResponseWriter.
	// net/http would add Date and Transfer-Encoding: chunked, which RFC 9110
	// §9.3.6 forbids on a 2xx CONNECT response: the client then waits for a
	// terminating chunk that never arrives and the command hangs.
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake error for %s: %v\n", host, err)
		return
	}
	defer tlsConn.Close()

	bw := bufio.NewWriterSize(tlsConn, 32*1024)
	reader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Error reading request: %v\n", err)
			}
			break
		}

		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = ""

		// Handle Expect: 100-continue.
		// http.ReadRequest does not perform the 100-continue handshake automatically
		// (unlike net/http.Server). If we try to log or forward the request body
		// without first sending 100 Continue, the client will never send the body,
		// causing a deadlock that manifests as an unexpected EOF or timeout.
		// Fix: send 100 Continue to the client immediately, then strip the header
		// so http.Transport does not attempt a second 100-continue round-trip to
		// the upstream.
		if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
			if _, err := fmt.Fprint(bw, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				break
			}
			if err := bw.Flush(); err != nil {
				break
			}
			req.Header.Del("Expect")
		}

		// Save before stripping so shouldClose can inspect the original value.
		reqConnHdr := req.Header.Get("Connection")

		shouldLog := matchesFilter(req)
		var reqID int
		if shouldLog {
			reqID = logRequest(req) // logs original headers
		}

		// WebSocket upgrades require a raw bidirectional tunnel; bypass the
		// normal hop-by-hop stripping and http.Client round-trip.
		if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			upConn, dialErr := tls.Dial("tcp", r.Host, &tls.Config{
				InsecureSkipVerify: insecureUpstream, //nolint:gosec // opt-in via --insecure-upstream
				ServerName:         host,
			})
			if dialErr != nil {
				if shouldLog {
					discardReqID(reqID)
				}
				warnTLSVerification(host, dialErr)
				writeConnError(bw, http.StatusBadGateway, dialErr.Error())
				bw.Flush() //nolint:errcheck
				break
			}
			spliceWebSocket(upConn, req, tlsConn, bw, reader)
			upConn.Close()
			if shouldLog {
				discardReqID(reqID)
			}
			break
		}

		removeHopByHopHeaders(req.Header) // strip before forwarding upstream

		resp, err := upstreamClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
			warnTLSVerification(host, err)
			if shouldLog {
				discardReqID(reqID)
			}
			writeConnError(bw, http.StatusBadGateway, err.Error())
			bw.Flush() //nolint:errcheck
			break
		}

		if shouldLog {
			logResponse(resp, reqID) // logs original response headers
		}

		shouldClose := strings.EqualFold(reqConnHdr, "close") ||
			strings.EqualFold(resp.Header.Get("Connection"), "close")

		removeHopByHopHeaders(resp.Header) // strip before forwarding downstream

		// The transport hands back a response with no known length whenever it
		// transparently decoded the body -- gunzipping drops Content-Length.
		// Response.Write would then delimit the body by closing the connection,
		// but this loop keeps the tunnel open for the next request, so the
		// client blocks waiting for an EOF that never arrives. Framing it as
		// chunked delimits the body without giving up keep-alive.
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 &&
			req.Method != http.MethodHead && bodyAllowedForStatus(resp.StatusCode) {
			resp.TransferEncoding = []string{"chunked"}
		}

		if err := resp.Write(bw); err != nil {
			resp.Body.Close()
			break
		}
		if err := bw.Flush(); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()

		if shouldClose {
			break
		}
	}
}

func main() { os.Exit(run()) }

// run holds the whole program body so that every exit path returns a code
// instead of calling os.Exit directly, which would skip cleanup.
func run() int {
	defer runCleanups()

	portFlag := flag.String("port", "8080", "proxy listen port; use 0 to pick a random free port")
	filterFlag := flag.String("filter", "", "only log requests whose URL or host contains this string (case-insensitive)")
	formatFlag := flag.String("format", "text", "output format: text | json")
	certTTLFlag := flag.Duration("cert-ttl", time.Hour, "how long to cache per-host TLS certificates; 0 disables caching")
	uiFlag := flag.Bool("ui", false, "launch interactive terminal UI (TUI)")
	recordFlag := flag.String("record", "", "path to write recorded traffic as NDJSON (appends if file exists)")
	harFlag := flag.String("har", "", "write captured traffic as HAR 1.2 JSON on exit")
	replayFlag := flag.String("replay", "", "path of a recorded NDJSON file to replay (skips proxy, no <command> needed)")
	replayTargetFlag := flag.String("replay-target", "", "override base URL for replay (e.g. https://staging.example.com)")
	replayDelayFlag := flag.Duration("replay-delay", 0, "pause between replayed requests")
	replayFailFlag := flag.Bool("replay-fail-on-diff", false, "exit with code 2 if any replayed response differs from the recording")
	insecureFlag := flag.Bool("insecure-upstream", false, "skip TLS certificate verification for upstream servers")
	maxBodyFlag := flag.Int("max-body", 1000, "max bytes of each body shown in output")
	maxCaptureFlag := flag.Int("max-capture", 1<<20, "max bytes of each body kept for --record/--har and decompression")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon [options] <command> [args...]")
		fmt.Fprintln(os.Stderr, "       httpmon --replay <file> [--replay-target <url>]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  httpmon curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --port 9090 aws s3 ls")
		fmt.Fprintln(os.Stderr, "  httpmon --filter /api curl https://example.com/api/v1/users")
		fmt.Fprintln(os.Stderr, "  httpmon --format json curl https://api.github.com | jq .")
		fmt.Fprintln(os.Stderr, "  httpmon --ui curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --record traffic.ndjson curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --har traffic.har curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --replay traffic.ndjson --replay-target https://staging.example.com")
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("httpmon %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}

	if *maxBodyFlag <= 0 || *maxCaptureFlag <= 0 {
		fmt.Fprintln(os.Stderr, "httpmon: --max-body and --max-capture must be greater than 0")
		return 1
	}
	if *maxCaptureFlag < *maxBodyFlag {
		fmt.Fprintln(os.Stderr, "httpmon: --max-capture must not be smaller than --max-body")
		return 1
	}
	displayMaxBody = *maxBodyFlag
	captureMaxBody = *maxCaptureFlag

	jsonMode = *formatFlag == "json"
	// Assigned before the replay branch so replay honours it too: a recording
	// captured from a self-signed or internal-CA host must be replayable.
	insecureUpstream = *insecureFlag

	// ── Replay mode: no proxy, no subprocess ─────────────────────────────────
	if *replayFlag != "" {
		return replayFile(*replayFlag, *replayTargetFlag, *replayDelayFlag, *replayFailFlag)
	}

	filterPattern = *filterFlag
	tuiMode = *uiFlag
	recordMode = *recordFlag != ""
	harMode = *harFlag != ""
	harPath = *harFlag
	certTTL = *certTTLFlag
	upstreamClient = newUpstreamClient(insecureUpstream)

	if recordMode {
		if err := openRecordFile(*recordFlag); err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: cannot open record file %s: %v\n", *recordFlag, err)
			return 1
		}
		addCleanup(func() { recordFile.Close() }) //nolint:errcheck
	}
	if certTTL > 0 {
		// Sweep expired entries at 1/6 of the TTL interval, minimum every minute.
		sweep := certTTL / 6
		if sweep < time.Minute {
			sweep = time.Minute
		}
		startCertJanitor(sweep)
	}

	cmdArgs := flag.Args()
	if len(cmdArgs) < 1 {
		flag.Usage()
		return 1
	}

	proxyCAPEM := &bytes.Buffer{}
	pem.Encode(proxyCAPEM, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	caCertPath, err := buildCABundle(proxyCAPEM.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: failed to build CA bundle: %v\n", err)
		return 1
	}
	addCleanup(func() { os.Remove(caCertPath) }) //nolint:errcheck

	ln, err := net.Listen("tcp", ":"+*portFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: failed to bind proxy on :%s: %v\n", *portFlag, err)
		return 1
	}
	proxyPort = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Bounds how long a connection may sit mid-header. Request bodies and
		// hijacked CONNECT tunnels are unaffected, so long-lived streams and
		// WebSocket splices still work.
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		if !jsonMode {
			fmt.Printf("Starting MITM proxy on :%s\n", proxyPort)
			fmt.Printf("CA bundle written to: %s\n", caCertPath)
			if sysCA := systemCABundle(); sysCA != "" {
				fmt.Printf("System CA bundle merged from: %s\n", sysCA)
			}
			if filterPattern != "" {
				fmt.Printf("Filter: %q\n", filterPattern)
			}
			if insecureUpstream {
				fmt.Println("Upstream TLS verification: DISABLED (--insecure-upstream)")
			}
		}
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			// Print rather than exit: the subprocess is already running and
			// os.Exit here would skip cleanup of the CA bundle.
			fmt.Fprintf(os.Stderr, "httpmon: proxy error: %v\n", err)
		}
	}()

	cmdName := filepath.Base(cmdArgs[0])

	if cmdName == "curl" {
		hasProxy := false
		hasCACert := false
		hasInsecure := false

		for _, arg := range cmdArgs {
			switch arg {
			case "-x", "--proxy":
				hasProxy = true
			case "--cacert":
				hasCACert = true
			case "-k", "--insecure":
				hasInsecure = true
			}
		}

		newArgs := []string{cmdArgs[0]}
		if !hasProxy {
			newArgs = append(newArgs, "-x", "http://localhost:"+proxyPort)
		}
		if !hasCACert && !hasInsecure {
			newArgs = append(newArgs, "--cacert", caCertPath)
		}
		newArgs = append(newArgs, cmdArgs[1:]...)
		cmdArgs = newArgs
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)

	proxyURL := "http://localhost:" + proxyPort
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"REQUESTS_CA_BUNDLE="+caCertPath,
		"SSL_CERT_FILE="+caCertPath,
		"NODE_EXTRA_CA_CERTS="+caCertPath,
	)

	if cmdName == "aws" {
		cmd.Env = append(cmd.Env, "AWS_CA_BUNDLE="+caCertPath)
	}

	if tuiMode {
		// In TUI mode the subprocess output is captured and shown after the UI exits.
		var subOut bytes.Buffer
		cmd.Stdout = &subOut
		cmd.Stderr = &subOut
		cmd.Stdin = os.Stdin

		exitCh := make(chan int, 1)
		go func() {
			code := 0
			if err := cmd.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					code = exitErr.ExitCode()
				} else {
					code = 1
				}
			}
			select {
			case tuiCh <- tuiDoneMsg{code}:
			default:
			}
			exitCh <- code
		}()

		runTUI()

		// Kill subprocess if user quit the TUI before it finished.
		if cmd.Process != nil {
			cmd.Process.Kill() //nolint:errcheck
		}
		code := <-exitCh

		if out := subOut.String(); out != "" {
			fmt.Fprintln(os.Stderr, "\n── Command Output ─────────────────────────────────────")
			fmt.Fprint(os.Stderr, out)
		}
		return finishHAR(code)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if !jsonMode {
		fmt.Printf("\nRunning: %s\n", strings.Join(cmdArgs, " "))
		fmt.Println(strings.Repeat("=", 60))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		if cmd.Process != nil {
			cmd.Process.Signal(sig) //nolint:errcheck
		}
	}()

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			exitCode = 1
		}
	}

	return finishHAR(exitCode)
}

// finishHAR writes the HAR file when --har is active, promoting a write failure
// to a non-zero exit code so a silent loss of captured traffic is impossible.
func finishHAR(exitCode int) int {
	if !harMode {
		return exitCode
	}
	if err := writeHARFile(harPath); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: failed to write HAR file %s: %v\n", harPath, err)
		if exitCode == 0 {
			return 1
		}
	}
	return exitCode
}
