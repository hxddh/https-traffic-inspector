package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

var (
	requestCounter int
	counterMu      sync.Mutex
	proxyPort      string
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	certCache      = make(map[string]*tls.Certificate)
	certMu         sync.Mutex
	upstreamClient *http.Client
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
func generateCert(host string) (*tls.Certificate, error) {
	certMu.Lock()
	defer certMu.Unlock()

	if cert, ok := certCache[host]; ok {
		return cert, nil
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

	certCache[host] = cert
	return cert, nil
}

func nextReqID() int {
	counterMu.Lock()
	defer counterMu.Unlock()
	requestCounter++
	return requestCounter
}

func logRequest(req *http.Request) {
	reqID := nextReqID()

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

	if req.Body != nil {
		body := peekBody(&req.Body, 1000)
		if len(body) > 0 {
			if isPrintable(req.Header) {
				fmt.Printf("\nBody:\n%s\n", string(body))
			} else {
				fmt.Printf("\nBody: [binary data, %d+ bytes]\n", len(body))
			}
		}
	}
	fmt.Println()
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

func logResponse(resp *http.Response) {
	fmt.Printf("\n\033[32m=== RESPONSE ===\033[0m\n")
	fmt.Printf("%s %s\n", resp.Proto, resp.Status)

	fmt.Println("\nHeaders:")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}

	if resp.Body != nil {
		body := peekBody(&resp.Body, 1000)
		if len(body) > 0 {
			fmt.Printf("\nBody:\n")
			if isPrintable(resp.Header) {
				fmt.Printf("%s\n", string(body))
			} else {
				fmt.Printf("[binary data, %d+ bytes]\n", len(body))
			}
		}
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
// Checked in order of prevalence across common Linux distros and macOS.
var systemCAPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",      // Debian / Ubuntu / Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",        // RHEL / CentOS / Fedora
	"/etc/ssl/cert.pem",                        // macOS / OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt",  // FreeBSD
	"/etc/ssl/ca-bundle.pem",                   // openSUSE
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
// by the proxy CA. This lets the subprocess verify both proxied and direct TLS connections.
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
	logRequest(req)

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

	logResponse(resp)

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("\n\033[33m=== CONNECT %s ===\033[0m\n\n", r.Host)

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
		// 200 already sent; we can only log at this point.
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

		logRequest(req)

		resp, err := sessionClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
			writeConnError(tlsConn, http.StatusBadGateway, err.Error())
			break
		}

		logResponse(resp)

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
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon [options] <command> [args...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  httpmon curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --port 9090 aws s3 ls")
		fmt.Fprintln(os.Stderr, "  httpmon --port 0 curl https://example.com   # random port")
	}
	flag.Parse()

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

	// Build a CA bundle that includes both system CAs and the proxy CA so the subprocess
	// can verify direct (non-proxied) TLS connections as well as proxied ones.
	caCertPath, err := buildCABundle(proxyCAPEM.Bytes())
	if err != nil {
		log.Fatal("Failed to build CA bundle:", err)
	}
	defer os.Remove(caCertPath)

	// Bind listener before launching the subprocess; this guarantees the proxy is ready.
	ln, err := net.Listen("tcp", ":"+*portFlag)
	if err != nil {
		log.Fatalf("Failed to bind proxy on :%s: %v", *portFlag, err)
	}
	// Resolve the actual port (important when --port 0 is used).
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
		fmt.Printf("Starting MITM proxy on :%s\n", proxyPort)
		fmt.Printf("CA bundle written to: %s\n", caCertPath)
		if sysCA := systemCABundle(); sysCA != "" {
			fmt.Printf("System CA bundle merged from: %s\n", sysCA)
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

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("\nRunning: %s\n", strings.Join(cmdArgs, " "))
	fmt.Println(strings.Repeat("=", 60))

	// Forward SIGINT/SIGTERM to the subprocess for graceful shutdown.
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
