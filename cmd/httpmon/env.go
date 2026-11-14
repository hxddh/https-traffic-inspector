package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// subprocessEnv builds the environment for the wrapped command: it points the
// command at httpmon and at the generated CA bundle.
//
// The inherited no-proxy list is cleared. A host named there would bypass
// httpmon completely and its traffic would go uncaptured with no indication
// that anything was missed — and the tools people wrap most often (go, pip,
// npm) are exactly the ones such lists tend to name. httpmon's own upstream
// client still applies the real NO_PROXY, so where the traffic ultimately goes
// is unchanged; it just passes through httpmon on the way.
//
// Most tools read SSL_CERT_FILE, but several keep their own variable and
// ignore it, failing verification or — worse — silently bypassing httpmon.
// Each variable here overrides an inherited value of the same name, which
// would otherwise point the tool at a bundle without httpmon's CA.
func subprocessEnv(base []string, proxyURL, caCertPath string) []string {
	env := append([]string{}, base...)
	env = append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=",
		"no_proxy=",
		// Node's built-in fetch ignores the proxy variables unless told
		// otherwise, so its requests went straight past httpmon.
		"NODE_USE_ENV_PROXY=1",
	)
	for _, k := range caBundleEnvVars {
		env = append(env, k+"="+caCertPath)
	}
	return env
}

// caBundleEnvVars name every variable httpmon sets to its CA bundle.
var caBundleEnvVars = []string{
	"SSL_CERT_FILE",       // OpenSSL-based tools, Go, Ruby, Python ssl
	"REQUESTS_CA_BUNDLE",  // Python requests
	"PIP_CERT",            // pip, which otherwise prefers its vendored certifi
	"AWS_CA_BUNDLE",       // botocore (aws CLI, boto3), which ignores the above
	"NODE_EXTRA_CA_CERTS", // Node.js
	"CURL_CA_BUNDLE",      // curl run from scripts, where -x/--cacert are not injected
	"GIT_SSL_CAINFO",      // git, whose libcurl ignores SSL_CERT_FILE
	"CARGO_HTTP_CAINFO",   // cargo
	"DENO_CERT",           // Deno
	// gRPC C-core (Python grpcio, Ruby, PHP…), which ships its own roots.
	"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
}

// ---- JVM ----
//
// Java ignores every variable above: it reads its proxy from system
// properties and trusts only the certificates in its truststore, which cannot
// be a PEM file. httpmon writes a PKCS#12 truststore holding the system CAs
// and its own, and passes the properties through JAVA_TOOL_OPTIONS, which
// every JVM reads at startup -- java, Gradle, Maven, sbt, Kotlin tools.

// javaTrustStorePassword protects nothing -- the store holds only public
// certificates -- but Java expects one; "changeit" is its conventional value.
const javaTrustStorePassword = "changeit"

// buildJavaTrustStore writes a PKCS#12 truststore containing the certificates
// in the PEM bundle at pemPath and returns its path.
func buildJavaTrustStore(pemPath string) (string, error) {
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	// LegacyDES is the encoding every Java release since 8 can read.
	p12, err := pkcs12.LegacyDES.EncodeTrustStore(certs, javaTrustStorePassword)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "httpmon-truststore-*.p12")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(p12); err != nil {
		f.Close()           //nolint:errcheck
		os.Remove(f.Name()) //nolint:errcheck
		return "", err
	}
	return f.Name(), f.Close()
}

// javaToolOptions returns the JAVA_TOOL_OPTIONS for the wrapped command: any
// inherited options first, then httpmon's, which take precedence because a
// JVM applies the last definition of a property.
//
// nonProxyHosts is cleared for the same reason NO_PROXY is: a host listed
// there would bypass httpmon unseen. Java's default list covers loopback.
func javaToolOptions(inherited, host, port, trustStore string) string {
	opts := []string{
		"-Dhttp.proxyHost=" + host, "-Dhttp.proxyPort=" + port,
		"-Dhttps.proxyHost=" + host, "-Dhttps.proxyPort=" + port,
		"-Dhttp.nonProxyHosts=",
		"-Djavax.net.ssl.trustStore=" + javaQuote(trustStore),
		"-Djavax.net.ssl.trustStoreType=PKCS12",
		"-Djavax.net.ssl.trustStorePassword=" + javaTrustStorePassword,
	}
	joined := strings.Join(opts, " ")
	if strings.TrimSpace(inherited) == "" {
		return joined
	}
	return strings.TrimSpace(inherited) + " " + joined
}

// javaQuote quotes a path containing spaces, which JAVA_TOOL_OPTIONS would
// otherwise split into separate options.
func javaQuote(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

// lookupEnv returns the last value of key in env, as exec does.
func lookupEnv(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}
