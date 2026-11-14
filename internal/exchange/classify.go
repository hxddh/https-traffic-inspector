package exchange

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Error kinds, so a program can act on a failure without parsing its text.
const (
	KindDNS          = "dns"
	KindRefused      = "refused"
	KindTimeout      = "timeout"
	KindTLSVerify    = "tls_verify"
	KindTLSHandshake = "tls_handshake"
	KindReset        = "reset"
	KindProxy        = "proxy"
	KindCanceled     = "canceled"
	// KindInjected is a failure a --fault rule caused on purpose.
	KindInjected     = "injected"
	KindOther        = "other"
)

// Kinds lists every error kind.
var Kinds = []string{KindDNS, KindRefused, KindTimeout, KindTLSVerify, KindTLSHandshake, KindReset, KindProxy, KindCanceled, KindInjected, KindOther}

// Classify returns the kind of an upstream failure.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var recordErr tls.RecordHeaderError
	var alert tls.AlertError
	var netErr net.Error
	var injected *InjectedError
	switch {
	case errors.As(err, &injected):
		return KindInjected
	case errors.Is(err, context.Canceled):
		return KindCanceled
	// The transport prefixes a failure to reach or negotiate with an
	// upstream proxy with "proxyconnect".
	case strings.Contains(msg, "proxyconnect") || strings.Contains(msg, "upstream proxy"):
		return KindProxy
	case errors.As(err, &dnsErr):
		return KindDNS
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority),
		errors.As(err, &hostnameErr), errors.As(err, &invalidErr):
		return KindTLSVerify
	case errors.As(err, &recordErr), errors.As(err, &alert), strings.Contains(msg, "tls: "):
		return KindTLSHandshake
	case errors.Is(err, syscall.ECONNREFUSED):
		return KindRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return KindReset
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return KindTimeout
	}
	return KindOther
}

// Describe classifies err and renders its message with displayURL in place of
// the URL the transport dialled, which inside a tunnel carries the CONNECT
// target's port ("https://example.com:443/…").
func Describe(err error, displayURL string) *Error {
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		msg = fmt.Sprintf("%s %s: %v", ue.Op, strconv.Quote(displayURL), ue.Err)
	}
	return &Error{Kind: Classify(err), Message: msg}
}

// InjectedError is a failure a --fault rule caused.
type InjectedError struct{ Rule string }

func (e *InjectedError) Error() string { return "injected by " + e.Rule }
