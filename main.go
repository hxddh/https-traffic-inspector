package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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
	caKey          *rsa.PrivateKey
	certCache      = make(map[string]*certEntry)
	certMu         sync.Mutex
	certTTL        = time.Hour // overridden by --cert-ttl flag
	upstreamClient *http.Client

	// set by flags
	filterPattern string
	jsonMode      bool
	tuiMode       bool

	// per-request start times for duration tracking (used in TUI and text mode)
	reqStartTimes = make(map[int]time.Time)
	reqStartMu    sync.Mutex
)

func init() {
	var err error
	caCert, caKey, err = generateCA()
	if err != nil {
		log.Fatal("Failed to generate CA:", err)
	}

	upstreamClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal("Failed to generate serial number:", err)
	}
	return n
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
// The mutex is held for the entire check-generate-store cycle to prevent TOCTOU races.
// Expired cache entries are replaced transparently.
func generateCert(host string) (*tls.Certificate, error) {
	certMu.Lock()
	defer certMu.Unlock()

	if e, ok := certCache[host]; ok && time.Now().Before(e.expiresAt) {
		return e.cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host, "*." + host},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	certCache[host] = &certEntry{cert: cert, expiresAt: time.Now().Add(certTTL)}
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

var jsonEnc = json.NewEncoder(os.Stdout)

func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

// ---- logging ----

// logRequest logs the request and returns the assigned request ID.
func logRequest(req *http.Request) int {
	reqID := nextReqID()

	reqStartMu.Lock()
	reqStartTimes[reqID] = time.Now()
	reqStartMu.Unlock()

	var bodyStr string
	if req.Body != nil {
		body := peekBody(&req.Body, 1000)
		if len(body) > 0 && isPrintable(req.Header) {
			bodyStr = string(body)
		} else if len(body) > 0 {
			bodyStr = fmt.Sprintf("[binary data, %d+ bytes]", len(body))
		}
	}

	if tuiMode {
		entry := &tuiEntry{
			id:         reqID,
			startTime:  reqStartTimes[reqID],
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
	dur := time.Since(start)

	var bodyStr string
	if resp.Body != nil {
		body := peekBody(&resp.Body, 1000)
		if len(body) > 0 && isPrintable(resp.Header) {
			bodyStr = string(body)
		} else if len(body) > 0 {
			bodyStr = fmt.Sprintf("[binary data, %d+ bytes]", len(body))
		}
	}

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
		jsonEnc.Encode(jsonResponse{ //nolint:errcheck
			ReqID:   reqID,
			Status:  resp.StatusCode,
			Proto:   resp.Proto,
			Headers: flattenHeaders(resp.Header),
			Body:    bodyStr,
		})
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

// peekBody reads up to n bytes from *body for logging, then reconstructs *body
// with a MultiReader so the full stream (including peeked bytes) can still be forwarded.
func peekBody(body *io.ReadCloser, n int) []byte {
	buf := make([]byte, n)
	nr, _ := io.ReadFull(*body, buf)
	buf = buf[:nr]
	*body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), *body))
	return buf
}

// isPrintable returns true when the Content-Type suggests the body is human-readable text.
// Also returns false for compressed payloads regardless of content type.
func isPrintable(header http.Header) bool {
	enc := header.Get("Content-Encoding")
	if enc != "" && enc != "identity" {
		return false
	}
	ct := strings.ToLower(header.Get("Content-Type"))
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

// writeConnError writes an HTTP error response directly onto a raw connection.
// Used inside a CONNECT tunnel where http.ResponseWriter is no longer available.
func writeConnError(conn net.Conn, statusCode int, msg string) {
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
	resp.Write(conn) //nolint:errcheck
}

// systemCABundle returns the path of the OS trusted CA bundle, or "" if not found.
var systemCAPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",     // Debian / Ubuntu / Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",       // RHEL / CentOS / Fedora
	"/etc/ssl/cert.pem",                       // macOS / OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
	"/etc/ssl/ca-bundle.pem",                  // openSUSE
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
		proxyReq.Header = req.Header
		resp, err := upstreamClient.Do(proxyReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyReq.Header = req.Header

	resp, err := upstreamClient.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logResponse(resp, reqID)

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if !jsonMode {
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

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hijack error for %s: %v\n", host, err)
		return
	}
	defer clientConn.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake error for %s: %v\n", host, err)
		return
	}
	defer tlsConn.Close()

	// One client per CONNECT session so upstream connections are reused within the tunnel.
	sessionClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

		shouldLog := matchesFilter(req)
		var reqID int
		if shouldLog {
			reqID = logRequest(req)
		}

		resp, err := sessionClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
			writeConnError(tlsConn, http.StatusBadGateway, err.Error())
			break
		}

		if shouldLog {
			logResponse(resp, reqID)
		}

		shouldClose := req.Header.Get("Connection") == "close" || resp.Header.Get("Connection") == "close"

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()

		if shouldClose {
			break
		}
	}
}

func main() {
	portFlag := flag.String("port", "8080", "proxy listen port; use 0 to pick a random free port")
	filterFlag := flag.String("filter", "", "only log requests whose URL or host contains this string (case-insensitive)")
	formatFlag := flag.String("format", "text", "output format: text | json")
	certTTLFlag := flag.Duration("cert-ttl", time.Hour, "how long to cache per-host TLS certificates; 0 disables caching")
	uiFlag := flag.Bool("ui", false, "launch interactive terminal UI (TUI)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon [options] <command> [args...]")
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
	}
	flag.Parse()

	filterPattern = *filterFlag
	jsonMode = *formatFlag == "json"
	tuiMode = *uiFlag
	certTTL = *certTTLFlag
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
		os.Exit(1)
	}

	proxyCAPEM := &bytes.Buffer{}
	pem.Encode(proxyCAPEM, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	caCertPath, err := buildCABundle(proxyCAPEM.Bytes())
	if err != nil {
		log.Fatal("Failed to build CA bundle:", err)
	}
	defer os.Remove(caCertPath)

	ln, err := net.Listen("tcp", ":"+*portFlag)
	if err != nil {
		log.Fatalf("Failed to bind proxy on :%s: %v", *portFlag, err)
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
		}
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy error: %v", err)
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
		os.Exit(code)
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

	os.Exit(exitCode)
}
