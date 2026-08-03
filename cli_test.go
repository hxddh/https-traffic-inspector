package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

// ---- cleanup ----

func TestCleanups_RunInReverseOrder(t *testing.T) {
	t.Cleanup(func() { cleanups = nil })
	cleanups = nil

	var order []string
	addCleanup(func() { order = append(order, "first") })
	addCleanup(func() { order = append(order, "second") })
	addCleanup(func() { order = append(order, "third") })
	runCleanups()

	want := []string{"third", "second", "first"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", order, want)
	}
}

func TestCleanups_DrainedAfterRun(t *testing.T) {
	t.Cleanup(func() { cleanups = nil })
	cleanups = nil

	calls := 0
	addCleanup(func() { calls++ })
	runCleanups()
	runCleanups() // a second call must not re-run anything

	if calls != 1 {
		t.Errorf("cleanup ran %d times, want 1", calls)
	}
}

// Regression: main() ended in os.Exit, so the deferred os.Remove of the CA
// bundle never ran and every invocation leaked a temp file.
func TestCleanups_RemovesCABundle(t *testing.T) {
	t.Cleanup(func() { cleanups = nil })
	cleanups = nil

	path, err := buildCABundle([]byte("-----BEGIN CERTIFICATE-----\n"))
	if err != nil {
		t.Fatal(err)
	}
	addCleanup(func() { os.Remove(path) }) //nolint:errcheck

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("CA bundle missing before cleanup: %v", err)
	}
	runCleanups()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		os.Remove(path) //nolint:errcheck
		t.Fatalf("CA bundle still present after cleanup (err=%v)", err)
	}
}

// ---- upstream TLS verification ----

func TestNewUpstreamClient_ConfigMatrix(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		c := newUpstreamClient(insecure)
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport is %T, want *http.Transport", c.Transport)
		}
		if got := tr.TLSClientConfig.InsecureSkipVerify; got != insecure {
			t.Errorf("InsecureSkipVerify = %v, want %v", got, insecure)
		}
	}
}

func TestUpstream_TLSVerifiedByDefault(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret")) //nolint:errcheck
	}))
	defer upstream.Close()

	saved := upstreamClient
	upstreamClient = newUpstreamClient(false)
	defer func() { upstreamClient = saved }()

	req, _ := http.NewRequest("GET", upstream.URL, nil)
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an unverifiable upstream", rr.Code)
	}
	body := strings.ToLower(rr.Body.String())
	if !strings.Contains(body, "certificate") && !strings.Contains(body, "x509") {
		t.Errorf("body = %q, want a certificate error", rr.Body.String())
	}
}

func TestUpstream_InsecureFlagBypasses(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret")) //nolint:errcheck
	}))
	defer upstream.Close()

	saved := upstreamClient
	upstreamClient = newUpstreamClient(true)
	defer func() { upstreamClient = saved }()

	req, _ := http.NewRequest("GET", upstream.URL, nil)
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with verification disabled", rr.Code)
	}
	if got := rr.Body.String(); got != "secret" {
		t.Errorf("body = %q, want %q", got, "secret")
	}
}

func TestIsTLSVerificationError(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	_, err := newUpstreamClient(false).Get(upstream.URL)
	if err == nil {
		t.Fatal("expected a verification failure")
	}
	if !isTLSVerificationError(err) {
		t.Errorf("isTLSVerificationError(%v) = false, want true", err)
	}

	if isTLSVerificationError(io.EOF) {
		t.Error("io.EOF classified as a TLS verification error")
	}
}

// ---- certificate SANs ----

func TestGenerateCert_IPHostUsesIPSAN(t *testing.T) {
	cert, err := generateCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseLeaf(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none for an IP host", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
}

func TestGenerateCert_DNSHostHasNoIPSAN(t *testing.T) {
	cert, err := generateCert("san.test.local")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseLeaf(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want none for a DNS host", leaf.IPAddresses)
	}
	// The old template also emitted a useless "*.<host>" entry.
	want := []string{"san.test.local"}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != want[0] {
		t.Errorf("DNSNames = %v, want %v", leaf.DNSNames, want)
	}
}

func parseLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	return x509.ParseCertificate(cert.Certificate[0])
}

// ---- body limits ----

func TestTruncateForDisplay_MarksTruncation(t *testing.T) {
	saved := displayMaxBody
	displayMaxBody = 10
	defer func() { displayMaxBody = saved }()

	got := truncateForDisplay(strings.Repeat("a", 50))
	if !strings.HasSuffix(got, truncationMarker) {
		t.Errorf("got %q, want the truncation marker appended", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 10)) {
		t.Errorf("got %q, want the first 10 bytes kept", got)
	}
}

func TestTruncateForDisplay_ShortBodyUnchanged(t *testing.T) {
	saved := displayMaxBody
	displayMaxBody = 100
	defer func() { displayMaxBody = saved }()

	if got := truncateForDisplay("short"); got != "short" {
		t.Errorf("got %q, want %q", got, "short")
	}
}

// Cutting at a fixed byte offset must not split a multi-byte rune.
func TestTruncateForDisplay_RuneBoundary(t *testing.T) {
	saved := displayMaxBody
	defer func() { displayMaxBody = saved }()

	body := strings.Repeat("日", 40) // 3 bytes each
	for _, limit := range []int{10, 11, 12, 13} {
		displayMaxBody = limit
		got := truncateForDisplay(body)
		if strings.ToValidUTF8(got, "") != got {
			t.Errorf("limit %d produced invalid UTF-8: %q", limit, got)
		}
	}
}

func TestRenderBody_RespectsCaptureLimit(t *testing.T) {
	savedCapture, savedDisplay := captureMaxBody, displayMaxBody
	savedRecord := recordMode
	captureMaxBody, displayMaxBody, recordMode = 64, 10, true
	defer func() {
		captureMaxBody, displayMaxBody, recordMode = savedCapture, savedDisplay, savedRecord
	}()

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	body := io.NopCloser(strings.NewReader(strings.Repeat("x", 500)))

	got := renderBody(&body, h)
	if len(got) != 64 {
		t.Errorf("len = %d, want 64 (captureMaxBody), not the display limit", len(got))
	}
}

// ---- replay ----

func writeRecording(t *testing.T, exchanges ...recordedExchange) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "rec-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, ex := range exchanges {
		if err := enc.Encode(ex); err != nil {
			t.Fatal(err)
		}
	}
	return f.Name()
}

func TestReplay_FailOnDiffStatusMismatch(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom")) //nolint:errcheck
	}))
	defer target.Close()

	path := writeRecording(t, recordedExchange{
		ID: 1, Method: "GET", URL: target.URL + "/health",
		Status: 200, StatusText: "200 OK", RespBody: "ok",
	})

	if code := replayFile(path, "", 0, false); code != 0 {
		t.Errorf("without --replay-fail-on-diff: code = %d, want 0", code)
	}
	if code := replayFile(path, "", 0, true); code != 2 {
		t.Errorf("with --replay-fail-on-diff: code = %d, want 2", code)
	}
}

func TestReplay_FailOnDiffCleanRun(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer target.Close()

	path := writeRecording(t, recordedExchange{
		ID: 1, Method: "GET", URL: target.URL + "/health",
		Status: 200, StatusText: "200 OK", RespBody: "ok",
	})

	if code := replayFile(path, "", 0, true); code != 0 {
		t.Errorf("code = %d, want 0 when nothing differs", code)
	}
}

// Recordings store decoded bodies, so a compressed replay response must be
// decompressed before comparison — otherwise every compressed endpoint reports
// a spurious diff on every replay.
func TestReplay_CompressedResponseComparesDecoded(t *testing.T) {
	const payload = `{"login":"octocat"}`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		bw := brotli.NewWriter(&buf)
		bw.Write([]byte(payload)) //nolint:errcheck
		bw.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		w.Write(buf.Bytes()) //nolint:errcheck
	}))
	defer target.Close()

	path := writeRecording(t, recordedExchange{
		ID: 1, Method: "GET", URL: target.URL + "/user",
		Status: 200, StatusText: "200 OK",
		RespBody: payload, // as stored by --record: already decoded
	})

	if code := replayFile(path, "", 0, true); code != 0 {
		t.Errorf("code = %d, want 0: a matching compressed body must not count as a diff", code)
	}
}

func TestDecodeForCompare(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("hello")) //nolint:errcheck
	gz.Close()

	h := http.Header{}
	h.Set("Content-Encoding", "gzip")
	if got := decodeForCompare(h, buf.Bytes()); got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}

	// Undecodable payloads fall back to a raw comparison rather than erroring.
	plain := http.Header{}
	if got := decodeForCompare(plain, []byte("raw")); got != "raw" {
		t.Errorf("got %q, want %q", got, "raw")
	}
	h.Set("Content-Encoding", "snappy")
	if got := decodeForCompare(h, []byte("raw")); got != "raw" {
		t.Errorf("got %q, want %q for an unsupported encoding", got, "raw")
	}
}

// A parse failure (exit 1) must stay distinguishable from a diff (exit 2).
func TestReplay_ParseErrorOutranksDiff(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{not json}\n") //nolint:errcheck
	f.Close()

	if code := replayFile(f.Name(), "", 0, true); code != 1 {
		t.Errorf("code = %d, want 1 for a malformed recording", code)
	}
}

func TestReplay_JSONOutput(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("changed")) //nolint:errcheck
	}))
	defer target.Close()

	path := writeRecording(t, recordedExchange{
		ID: 7, Method: "GET", URL: target.URL + "/thing",
		Status: 200, StatusText: "200 OK", RespBody: "original",
	})

	savedMode, savedEnc := jsonMode, jsonEnc
	var out bytes.Buffer
	jsonMode = true
	jsonEnc = json.NewEncoder(&out)
	defer func() { jsonMode, jsonEnc = savedMode, savedEnc }()

	replayFile(path, "", 0, false)

	var res replayResult
	line := strings.TrimSpace(out.String())
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	if res.ID != 7 || res.RecordedStatus != 200 || res.ActualStatus != 201 {
		t.Errorf("res = %+v, want id=7 recorded=200 actual=201", res)
	}
	if res.StatusMatch || res.BodyMatch {
		t.Errorf("res = %+v, want both comparisons to report a difference", res)
	}
	if !res.Differs() {
		t.Error("Differs() = false, want true")
	}
}

// ---- version ----

func TestVersion_DefaultAndHARCreator(t *testing.T) {
	if version == "" {
		t.Fatal("version must never be empty")
	}

	harEntriesMu.Lock()
	harEntries = nil
	harEntriesMu.Unlock()

	path := t.TempDir() + "/out.har"
	if err := writeHARFile(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var hf harFile
	if err := json.Unmarshal(data, &hf); err != nil {
		t.Fatal(err)
	}
	if hf.Log.Creator.Version != version {
		t.Errorf("creator.version = %q, want %q", hf.Log.Creator.Version, version)
	}
	if hf.Log.Creator.Name != "httpmon" {
		t.Errorf("creator.name = %q, want httpmon", hf.Log.Creator.Name)
	}
}
