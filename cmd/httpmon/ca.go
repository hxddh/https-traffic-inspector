package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// certEntry wraps a TLS certificate with an expiry time for cache TTL enforcement.
type certEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

var (
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	certCache = make(map[string]*certEntry)
	certMu    sync.Mutex
	certTTL   = time.Hour // overridden by --cert-ttl flag
)

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
			CommonName:   caCommonName(),
		},
		// Backdated a little so a client whose clock runs slightly behind
		// does not reject a certificate that is not valid yet.
		NotBefore:             time.Now().Add(-time.Hour),
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
		NotBefore:   time.Now().Add(-time.Hour),
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
	name := f.Name()
	f.Close() //nolint:errcheck
	return name, writeCABundle(name, proxyCAPEM)
}

// writeCABundle writes the system roots followed by httpmon's CA to path.
func writeCABundle(path string, proxyCAPEM []byte) error {
	var data []byte
	if sysCA := systemCABundle(); sysCA != "" {
		if b, err := os.ReadFile(sysCA); err == nil {
			data = append(b, '\n')
		}
	}
	data = append(data, proxyCAPEM...)
	return os.WriteFile(path, data, 0o600)
}

// caCommonName names the CA after the machine and the day it was made, so a
// persisted CA can be recognised in a trust store and told apart from others.
func caCommonName() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("httpmon CA (%s, %s)", host, time.Now().Format("2006-01-02"))
}

// ---- persistent CA (--ca-dir) ----
//
// By default the CA lives only in memory for one run, which is enough for any
// tool that reads httpmon's environment. Devices and runtimes that keep their
// own trust store -- a phone, an emulator, a browser profile, a container
// image -- need a CA that outlives the run, so they can be told to trust it
// once.

const (
	caCertFile = "httpmon-ca.pem"
	caKeyFile  = "httpmon-ca.key"
)

// loadOrCreateCA loads the CA kept in dir, creating it on first use. It
// reports the path of the certificate file and whether it was just created.
func loadOrCreateCA(dir string) (certPath string, created bool, err error) {
	certPath = filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, key, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return "", false, fmt.Errorf("%s: %w", dir, err)
		}
		if time.Now().After(cert.NotAfter) {
			return "", false, fmt.Errorf("the CA in %s expired on %s; delete it to create a new one", dir, cert.NotAfter.Format("2006-01-02"))
		}
		caCert, caKey = cert, key
		resetCertCache()
		return certPath, false, nil
	}
	if !errors.Is(certErr, fs.ErrNotExist) || !errors.Is(keyErr, fs.ErrNotExist) {
		if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
			return "", false, certErr
		}
		if keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist) {
			return "", false, keyErr
		}
		return "", false, fmt.Errorf("%s holds only half of a CA (%s and %s must both exist); delete it to start again", dir, caCertFile, caKeyFile)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false, err
	}
	cert, key, err := generateCA()
	if err != nil {
		return "", false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", false, err
	}
	// The key first, created exclusively and private: anyone holding it can
	// intercept the traffic of every device that trusts this CA.
	if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", false, err
	}
	if err := writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		return "", false, err
	}
	caCert, caKey = cert, key
	resetCertCache()
	return certPath, true, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	return f.Close()
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, errors.New("no certificate in " + caCertFile)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, errors.New(caCertFile + " is not a CA certificate")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("no private key in " + caKeyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New(caKeyFile + " is not an ECDSA key")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New(caKeyFile + " does not belong to " + caCertFile)
	}
	return cert, key, nil
}

func resetCertCache() {
	certMu.Lock()
	certCache = make(map[string]*certEntry)
	certMu.Unlock()
}

// caPEM returns the CA certificate in PEM form.
func caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
}
