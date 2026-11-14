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
	"strings"
	"syscall"
	"testing"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
)

func TestSummaryLine(t *testing.T) {
	for _, tc := range []struct {
		e    Exchange
		want string
	}{
		{Exchange{ID: 10, Method: "GET", URL: "https://api.example.com/fail", Status: 500, DurationMs: 44.2, Hint: "db_timeout",
			Response: &Message{Body: &body.Rendered{Size: 105}}},
			"#10 GET api.example.com/fail → 500 db_timeout (44ms, 105 B)"},
		{Exchange{ID: 11, Method: "GET", URL: "http://127.0.0.1:1/x", DurationMs: 0.3, Error: &Error{Kind: KindRefused, Message: "…"}},
			"#11 GET 127.0.0.1:1/x → ERR refused (0ms)"},
		{Exchange{ID: 3, Method: "GET", URL: "wss://h/ws", Status: 101, DurationMs: 4200,
			WebSocket: &WebSocket{Messages: make([]WSMessage, 12)}},
			"#3 GET h/ws → 101 websocket, 12 messages (4.2s)"},
		{Exchange{ID: 2, Method: "POST", URL: "https://h/pkg.Svc/Get", Status: 200, DurationMs: 1, GRPC: &GRPCStatus{Code: 5, Name: "NOT_FOUND"}},
			"#2 POST h/pkg.Svc/Get → 200 grpc NOT_FOUND (1ms, 0 B)"},
	} {
		if got := tc.e.SummaryLine(); got != tc.want {
			t.Errorf("SummaryLine() = %q\n               want %q", got, tc.want)
		}
	}
}

func TestDigest(t *testing.T) {
	var d Digest
	for i, st := range []int{200, 200, 201, 500} {
		d.Add(&Exchange{ID: i + 1, Status: st, DurationMs: float64(10 * (i + 1))})
	}
	d.Add(&Exchange{ID: 5, Error: &Error{Kind: KindRefused}})
	d.Matched = []int{4, 5}
	d.Incomplete = 1
	want := "── 5 exchanges: 3×2xx, 1×5xx, 1 failed, 1 incomplete · slowest #4 40ms · --fail-on matched #4, #5"
	if got := d.String(); got != want {
		t.Errorf("Digest = %q\n    want %q", got, want)
	}
}

func TestFailOn(t *testing.T) {
	f, err := ParseFailOn("5xx, 404 ,error")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		e    Exchange
		want bool
	}{
		{Exchange{Status: 503}, true},
		{Exchange{Status: 404}, true},
		{Exchange{Status: 403}, false},
		{Exchange{Status: 200}, false},
		{Exchange{Error: &Error{Kind: KindDNS}}, true},
	} {
		if got := f.Match(&tc.e); got != tc.want {
			t.Errorf("Match(status %d, error %v) = %v, want %v", tc.e.Status, tc.e.Error, got, tc.want)
		}
	}
	for _, bad := range []string{"6xx", "abc", "99"} {
		if _, err := ParseFailOn(bad); err == nil {
			t.Errorf("ParseFailOn(%q) accepted", bad)
		}
	}
	var none *FailOn
	if none.Match(&Exchange{Status: 500}) {
		t.Error("a nil FailOn matched")
	}
}

func TestClassify(t *testing.T) {
	opErr := func(err error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: err} }
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", Name: "x.invalid"}, KindDNS},
		{opErr(&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}), KindRefused},
		{opErr(&os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}), KindReset},
		{io.ErrUnexpectedEOF, KindReset},
		{context.DeadlineExceeded, KindTimeout},
		{os.ErrDeadlineExceeded, KindTimeout},
		{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, KindTLSVerify},
		{x509.HostnameError{Host: "h", Certificate: &x509.Certificate{}}, KindTLSVerify},
		{tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, KindTLSHandshake},
		{errors.New("remote error: tls: handshake failure"), KindTLSHandshake},
		{fmt.Errorf("proxyconnect tcp: %w", opErr(syscall.ECONNREFUSED)), KindProxy},
		{context.Canceled, KindCanceled},
		{errors.New("something else"), KindOther},
	} {
		wrapped := &url.Error{Op: "Get", URL: "https://example.com:443/", Err: tc.err}
		if got := Classify(wrapped); got != tc.want {
			t.Errorf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// Regression: failures named the address the transport dialled --
// "https://example.com:443/" inside a tunnel -- not the URL the client used.
func TestDescribe_UsesDisplayURL(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://example.com:443/x", Err: syscall.ECONNREFUSED}
	e := Describe(err, "https://example.com/x")
	if strings.Contains(e.Message, ":443") || !strings.Contains(e.Message, "https://example.com/x") {
		t.Errorf("message = %q", e.Message)
	}
	if e.Kind != KindRefused {
		t.Errorf("kind = %q", e.Kind)
	}
}

func TestReader_RejectsOtherVersions(t *testing.T) {
	r := NewReader(strings.NewReader(`{"v":3,"id":1,"method":"GET","url":"u","time":"t","kind":"http","request":{"headers":{}}}` + "\n\n" + `{"v":2,"seq":1}` + "\n"))
	if e, err := r.Next(); err != nil || e.ID != 1 {
		t.Fatalf("first = %+v, %v", e, err)
	}
	if _, err := r.Next(); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Errorf("second err = %v, want a version error", err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("third err = %v, want EOF", err)
	}
}
