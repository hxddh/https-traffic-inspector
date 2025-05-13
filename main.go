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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	requestCounter int
	mutex          sync.Mutex
	proxyPort      = "8080"
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	certCache      = make(map[string]*tls.Certificate)
	certMutex      sync.Mutex
)

func init() {
	var err error
	caCert, caKey, err = generateCA()
	if err != nil {
		log.Fatal("Failed to generate CA:", err)
	}
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
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

func generateCert(host string) (*tls.Certificate, error) {
	certMutex.Lock()
	if cert, ok := certCache[host]; ok {
		certMutex.Unlock()
		return cert, nil
	}
	certMutex.Unlock()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
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

	certMutex.Lock()
	certCache[host] = cert
	certMutex.Unlock()

	return cert, nil
}

func logRequest(req *http.Request) {
	mutex.Lock()
	requestCounter++
	reqID := requestCounter
	mutex.Unlock()

	fmt.Printf("\n\033[36m=== REQUEST #%d ===\033[0m\n", reqID)
	fmt.Printf("Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("%s %s %s\n", req.Method, req.URL.String(), req.Proto)
	fmt.Printf("Host: %s\n", req.Host)

	if strings.Contains(req.Host, ".amazonaws.com") && strings.Contains(req.URL.Path, "/") {
		pathParts := strings.SplitN(req.URL.Path, "/", 3)
		if len(pathParts) >= 2 && pathParts[1] != "" {
			fmt.Printf("\033[93mS3 Bucket: %s\033[0m\n", pathParts[1])
			if len(pathParts) > 2 && pathParts[2] != "" {
				fmt.Printf("\033[93mS3 Key/Prefix: %s\033[0m\n", pathParts[2])
			}
		}
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
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		if len(body) > 0 {
			fmt.Printf("\nBody:\n%s\n", string(body))
		}
	}
	fmt.Println()
}

func logResponse(resp *http.Response) {
	fmt.Printf("\n\033[32m=== RESPONSE ===\033[0m\n")
	fmt.Printf("%s %s\n", resp.Proto, resp.Status)

	fmt.Println("\nHeaders:")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}

	if resp.Body != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if len(body) > 0 {
			fmt.Printf("\nBody:\n")
			if len(body) > 1000 {
				fmt.Printf("%s\n[... %d more bytes ...]\n", string(body[:1000]), len(body)-1000)
			} else {
				fmt.Printf("%s\n", string(body))
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 60))
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	logRequest(req)

	targetURL := req.URL
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

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
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
	io.Copy(w, resp.Body)
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

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error reading request: %v\n", err)
			}
			break
		}

		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = ""

		logRequest(req)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}

		logResponse(resp)

		resp.Write(tlsConn)
		resp.Body.Close()

		if req.Header.Get("Connection") == "close" || resp.Header.Get("Connection") == "close" {
			break
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: httpmon <command> [args...]")
		fmt.Println("Example: httpmon curl https://api.github.com")
		os.Exit(1)
	}

	caCertPEM := &bytes.Buffer{}
	pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	caCertFile := "/tmp/httpmon-ca.crt"
	err := os.WriteFile(caCertFile, caCertPEM.Bytes(), 0644)
	if err != nil {
		log.Fatal("Failed to write CA cert:", err)
	}

	server := &http.Server{
		Addr: ":" + proxyPort,
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
		fmt.Printf("CA certificate written to: %s\n", caCertFile)
		if err := server.ListenAndServe(); err != nil {
			log.Fatal("Proxy error:", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	cmdArgs := os.Args[1:]

	if strings.Contains(cmdArgs[0], "curl") {
		hasProxy := false
		hasCACert := false
		hasInsecure := false

		for _, arg := range cmdArgs {
			if arg == "-x" || arg == "--proxy" {
				hasProxy = true
			}
			if arg == "--cacert" {
				hasCACert = true
			}
			if arg == "-k" || arg == "--insecure" {
				hasInsecure = true
			}
		}

		newArgs := []string{cmdArgs[0]}
		if !hasProxy {
			newArgs = append(newArgs, "-x", "http://localhost:"+proxyPort)
		}
		if !hasCACert && !hasInsecure {
			newArgs = append(newArgs, "--cacert", caCertFile)
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
		"REQUESTS_CA_BUNDLE="+caCertFile,
		"SSL_CERT_FILE="+caCertFile,
		"NODE_EXTRA_CA_CERTS="+caCertFile,
	)

	if strings.Contains(cmdArgs[0], "aws") {
		cmd.Env = append(cmd.Env, "AWS_CA_BUNDLE="+caCertFile)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("\nRunning: %s\n", strings.Join(cmdArgs, " "))
	fmt.Println(strings.Repeat("=", 60))

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}
