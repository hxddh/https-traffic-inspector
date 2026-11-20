package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hxddh/https-traffic-inspector/v5/internal/body"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ---- terminal safety ----

// Regression: response bodies were written to the terminal as they came, so a
// server could write the user's clipboard (OSC 52) or clear the screen.
func TestTextOutput_ServerEscapeSequencesAreNeutralised(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "hello \x1b]52;c;ZXZpbA==\x07 \x1b[2J end") //nolint:errcheck
	}))
	defer upstream.Close()
	out := captureText(t)

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.RequestURI = ""
	handleHTTP(httptest.NewRecorder(), req)

	text := out.String()
	if strings.ContainsRune(text, 0x1b) || strings.ContainsRune(text, 0x07) {
		t.Fatalf("raw control characters reached the output:\n%q", text)
	}
	if !strings.Contains(text, `\x1b]52;c;`) {
		t.Errorf("the escape should be shown, escaped; output:\n%s", text)
	}
}

func captureText(t *testing.T) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	saved := swapTextOut(out)
	t.Cleanup(func() { swapTextOut(saved) })
	return out
}

func captureJSON(t *testing.T) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	jsonEncMu.Lock()
	savedMode, savedEnc := jsonMode, jsonEnc
	jsonMode, jsonEnc = true, json.NewEncoder(out)
	jsonEncMu.Unlock()
	t.Cleanup(func() {
		jsonEncMu.Lock()
		jsonMode, jsonEnc = savedMode, savedEnc
		jsonEncMu.Unlock()
	})
	return out
}

// ---- fidelity ----

// Regression: inside a tunnel the upstream request took its Host from the
// CONNECT target, so every HTTPS upstream saw "Host: example.com:443", and a
// request whose Host differed from the tunnel went to the wrong virtual host.
func TestTunnel_ClientHostReachesUpstream(t *testing.T) {
	gotHost := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost <- r.Host
	}))
	defer upstream.Close()
	useInsecureUpstream(t)
	client, done := proxiedClient(t)
	defer done()

	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Host = "virtual.example"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck
	if h := <-gotHost; h != "virtual.example" {
		t.Errorf("upstream saw Host %q, want virtual.example", h)
	}
}

func TestRequestDisplayURL_DropsDefaultPort(t *testing.T) {
	for _, tc := range []struct{ scheme, target, host, want string }{
		{"https", "api.example.com:443", "api.example.com", "https://api.example.com/p"},
		{"https", "api.example.com:443", "", "https://api.example.com/p"},
		{"https", "api.example.com:8443", "api.example.com:8443", "https://api.example.com:8443/p"},
		{"http", "api.example.com:80", "", "http://api.example.com/p"},
	} {
		req := &http.Request{URL: &url.URL{Scheme: tc.scheme, Host: tc.target, Path: "/p"}, Host: tc.host}
		if got := requestDisplayURL(req); got != tc.want {
			t.Errorf("requestDisplayURL(%s, host %q) = %q, want %q", tc.target, tc.host, got, tc.want)
		}
	}
}

// Regression: the upstream transport added Accept-Encoding: gzip to requests
// that had none, and curl's Proxy-Connection header reached the origin.
func TestForward_UpstreamSeesTheClientsHeaders(t *testing.T) {
	got := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}))
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.RequestURI = ""
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	handleHTTP(httptest.NewRecorder(), req)

	h := <-got
	if v := h.Get("Accept-Encoding"); v != "" {
		t.Errorf("upstream got Accept-Encoding %q the client never sent", v)
	}
	if v := h.Get("Proxy-Connection"); v != "" {
		t.Errorf("Proxy-Connection reached the upstream: %q", v)
	}
}

// ---- credential masking ----

func TestTextOutput_MasksCredentialsUnlessShown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	const token = "Bearer s3cr3t-t0ken-value-0123456789"

	for _, show := range []bool{false, true} {
		out := captureText(t)
		saved := showSecrets
		showSecrets = show
		req := httptest.NewRequest(http.MethodGet, upstream.URL+"/?api_key=k3y-0123456789abcdef", nil)
		req.RequestURI = ""
		req.Header.Set("Authorization", token)
		handleHTTP(httptest.NewRecorder(), req)
		showSecrets = saved

		text := out.String()
		leaked := strings.Contains(text, "s3cr3t-t0ken") || strings.Contains(text, "k3y-0123456789abcdef")
		if !show && leaked {
			t.Errorf("credentials shown without --show-secrets:\n%s", text)
		}
		if show && !leaked {
			t.Errorf("--show-secrets did not show the credentials:\n%s", text)
		}
	}
}

// ---- failures ----

// Regression: an exchange that got no response was dropped from every output:
// the record and HAR left it out, JSON emitted nothing, and the TUI showed it
// as pending forever.
func TestFailure_ReportedInEveryOutput(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	out := captureJSON(t)
	recPath := filepath.Join(t.TempDir(), "rec.ndjson")
	useRecord(t, recPath)

	req := httptest.NewRequest(http.MethodGet, deadURL+"/gone", nil)
	req.RequestURI = ""
	rr := httptest.NewRecorder()
	handleHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}

	var failure exchange.Exchange
	if err := json.Unmarshal(bytes.TrimSpace([]byte(out.String())), &failure); err != nil {
		t.Fatalf("JSON output is not one exchange: %v\n%s", err, out.String())
	}
	if failure.Error == nil || failure.Error.Kind != exchange.KindRefused || failure.Response != nil {
		t.Errorf("exchange = %+v, want error kind refused and no response", failure)
	}
	if strings.Contains(failure.Error.Message, ":80/") {
		t.Errorf("error message names the dialled address, not the URL: %q", failure.Error.Message)
	}

	recs := readRecordFile(t, recPath)
	if len(recs) != 1 || recs[0].Error == nil || recs[0].Status != 0 {
		t.Errorf("record = %+v, want one entry with an error and no status", recs)
	}
	var entries []exchange.HAREntry
	for _, r := range recs {
		entries = append(entries, exchange.ToHAR(r))
	}
	if len(entries) != 1 || entries[0].Response.Error == "" || entries[0].Response.Status != 0 {
		t.Errorf("HAR = %+v, want one entry with status 0 and _error", entries)
	}
}

func TestTUI_FailedEntryIsNotPending(t *testing.T) {
	m := newTestModel(t, 100, 40)
	m = send(t, m, tuiReqMsg{&tuiEntry{id: 1, method: "GET", host: "h", path: "/", pending: true}})
	m = send(t, m, tuiFailMsg{reqID: 1, err: "dial tcp: connection refused", duration: time.Millisecond})
	if m.entries[0].pending {
		t.Fatal("failed entry still pending")
	}
	if v := m.View(); !strings.Contains(v, "ERR") {
		t.Errorf("list does not show the failure:\n%s", v)
	}
	if d := renderEntryDetail(m.entries[0], false); !strings.Contains(d, "connection refused") {
		t.Errorf("detail does not show the error:\n%s", d)
	}
}

func useRecord(t *testing.T, path string) {
	t.Helper()
	savedRM, savedCaptures := recordMode, captures
	recordMode, captures = true, newExchangeJoiner()
	if err := openRecordFile(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		recordFile.Close() //nolint:errcheck
		recordFile, recordEncoder = nil, nil
		recordMode, captures = savedRM, savedCaptures
	})
}

// ---- record v2 and replay ----

// Regression: binary bodies were recorded as "[binary data, N+ bytes]", so
// replay sent the placeholder as the request body and reported every binary
// response as changed.
func TestRecordReplay_BinaryBodiesRoundTrip(t *testing.T) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	var received [][]byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = append(received, b)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Add("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
		w.Header().Add("Set-Cookie", "b=2")
		w.Write(bytes.Repeat([]byte{0xff, 0x00, 0x9b}, 100)) //nolint:errcheck
	}))
	defer upstream.Close()

	recPath := filepath.Join(t.TempDir(), "rec.ndjson")
	func() {
		useRecord(t, recPath)
		captureText(t)
		req := httptest.NewRequest(http.MethodPost, upstream.URL+"/up", bytes.NewReader(payload))
		req.RequestURI = ""
		req.Header.Set("Content-Type", "application/octet-stream")
		handleHTTP(httptest.NewRecorder(), req)
	}()

	recs := readRecordFile(t, recPath)
	if len(recs) != 1 {
		t.Fatalf("recorded %d exchanges", len(recs))
	}
	if rb := recs[0].Request.Body; rb == nil || rb.Raw == nil || rb.Raw.Encoding != "base64" || rb.Size != 300 {
		t.Errorf("request body = %+v, want 300 bytes in base64", rb)
	}
	cookies := recs[0].Response.Headers["Set-Cookie"]
	if len(cookies) != 2 {
		t.Errorf("Set-Cookie headers = %q, want both kept separately", cookies)
	}

	out := captureText(t)
	if code := replayFile(recPath, "", 0, true); code != 0 {
		t.Fatalf("replay exit = %d, want 0; output:\n%s", code, out.String())
	}
	if len(received) != 2 || !bytes.Equal(received[1], payload) {
		t.Errorf("replayed upload differs from the original (%d bytes)", len(received[len(received)-1]))
	}
}

// Without backward compatibility, a record of another version is refused
// with a message that says so, not replayed half-understood.
func TestReplay_RejectsOtherRecordVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.ndjson")
	os.WriteFile(path, []byte(`{"v":2,"session":"s","seq":1,"method":"GET","url":"http://x/"}`+"\n"), 0o600) //nolint:errcheck
	captureText(t)
	if code := replayFile(path, "", 0, false); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestReplay_SkipsWebSocketsFailuresAndRedacted(t *testing.T) {
	out := captureText(t)
	lines := []*exchange.Exchange{
		{V: 3, Session: "s", ID: 1, Kind: "websocket", Method: "GET", URL: "http://127.0.0.1:1/ws", Status: 101},
		{V: 3, Session: "s", ID: 2, Kind: "http", Method: "GET", URL: "http://127.0.0.1:1/x", Error: &exchange.Error{Kind: "refused"}},
		{V: 3, Session: "s", ID: 3, Kind: "http", Method: "GET", URL: "http://127.0.0.1:1/y", Status: 200,
			Redacted: true, Request: exchange.Message{Headers: exchange.Headers{"Authorization": {"Bearer abcd…(40 chars)"}}}},
		{V: 3, Session: "s", ID: 4, Kind: "http", Method: "POST", URL: "http://127.0.0.1:1/z", Status: 200,
			Request: exchange.Message{Body: &body.Rendered{Size: 10, Raw: &body.Raw{Encoding: "utf8", Data: "part", Truncated: true}}}},
	}
	path := filepath.Join(t.TempDir(), "v3.ndjson")
	var b bytes.Buffer
	for _, l := range lines {
		json.NewEncoder(&b).Encode(l) //nolint:errcheck
	}
	os.WriteFile(path, b.Bytes(), 0o600) //nolint:errcheck
	if code := replayFile(path, "", 0, true); code != 0 {
		t.Fatalf("exit = %d; output:\n%s", code, out.String())
	}
	if n := strings.Count(out.String(), "SKIP"); n != 4 {
		t.Errorf("skipped %d, want 4; output:\n%s", n, out.String())
	}
}

// ---- HAR ----

func TestHAR_BinaryBodyIsBase64(t *testing.T) {
	e := exchange.ToHAR(&exchange.Exchange{
		Method: "GET", URL: "http://h/", Status: 200, StatusText: "OK",
		Response: &exchange.Message{
			Headers: exchange.Headers{"Content-Type": {"image/png"}},
			Body:    &body.Rendered{Size: 5, ContentType: "image/png", Raw: body.NewRaw([]byte{0x89, 'P', 'N', 'G', 0xff}, false)},
		},
	})
	if e.Response.Content.Encoding != "base64" || e.Response.Content.Text != "iVBOR/8=" {
		t.Errorf("content = %+v, want base64 of the bytes", e.Response.Content)
	}
	if e.Response.BodySize != 5 {
		t.Errorf("bodySize = %d, want 5", e.Response.BodySize)
	}
}

// ---- WebSocket ----

// wsFrame builds one frame; a client frame is masked.
func wsFrame(fin bool, rsv1 bool, opcode byte, payload []byte, masked bool) []byte {
	var b bytes.Buffer
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	b.WriteByte(b0)
	var m byte
	if masked {
		m = 0x80
	}
	switch {
	case len(payload) < 126:
		b.WriteByte(m | byte(len(payload)))
	case len(payload) < 1<<16:
		b.WriteByte(m | 126)
		binary.Write(&b, binary.BigEndian, uint16(len(payload))) //nolint:errcheck
	default:
		b.WriteByte(m | 127)
		binary.Write(&b, binary.BigEndian, uint64(len(payload))) //nolint:errcheck
	}
	if masked {
		key := [4]byte{1, 2, 3, 4}
		b.Write(key[:])
		for i, c := range payload {
			b.WriteByte(c ^ key[i%4])
		}
	} else {
		b.Write(payload)
	}
	return b.Bytes()
}

func TestWSParser_FragmentedMaskedAndControl(t *testing.T) {
	var got []wsMessage
	p := &wsParser{fromClient: true, onMessage: func(m wsMessage) { got = append(got, m) }}
	stream := append(wsFrame(false, false, wsText, []byte("hel"), true), wsFrame(true, false, wsPing, []byte("p"), true)...)
	stream = append(stream, wsFrame(true, false, wsContinuation, []byte("lo"), true)...)
	stream = append(stream, wsFrame(true, false, wsClose, append([]byte{0x03, 0xe8}, "bye"...), true)...)
	// Fed one byte at a time, as a slow connection might deliver it.
	for i := range stream {
		p.Write(stream[i : i+1]) //nolint:errcheck
	}
	if len(got) != 3 {
		t.Fatalf("got %d messages, want 3: %+v", len(got), got)
	}
	if got[0].opcode != wsPing || got[1].opcode != wsText || string(got[1].data) != "hello" {
		t.Errorf("messages = %+v", got)
	}
	if got[2].closeCode != 1000 || got[2].closeReason != "bye" {
		t.Errorf("close = %+v", got[2])
	}
}

// permessage-deflate with context takeover: later messages refer back to
// earlier ones, so each must be decoded with the window the sender kept.
func TestWSParser_DeflateWithContextTakeover(t *testing.T) {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	var frames []byte
	texts := []string{strings.Repeat("abcdefgh", 30) + " #0", strings.Repeat("abcdefgh", 30) + " #1"}
	for _, s := range texts {
		buf.Reset()
		fw.Write([]byte(s)) //nolint:errcheck
		fw.Flush()          //nolint:errcheck
		comp := bytes.TrimSuffix(buf.Bytes(), []byte{0, 0, 0xff, 0xff})
		frames = append(frames, wsFrame(true, true, wsText, comp, false)...)
	}
	var got []wsMessage
	p := &wsParser{deflate: true, onMessage: func(m wsMessage) { got = append(got, m) }}
	p.Write(frames) //nolint:errcheck
	if len(got) != 2 {
		t.Fatalf("got %d messages", len(got))
	}
	for i, m := range got {
		if string(m.data) != texts[i] || m.undecodable {
			t.Errorf("message %d = %q (undecodable=%v), want %q", i, m.data, m.undecodable, texts[i])
		}
	}
	if got[1].size >= int64(len(texts[1]))/4 {
		t.Errorf("second message was %d bytes on the wire; context takeover should shrink it", got[1].size)
	}
}

func TestParseDeflateExtension(t *testing.T) {
	d, c, s := parseDeflateExtension([]string{"permessage-deflate; client_no_context_takeover; server_max_window_bits=10"})
	if !d || !c || s {
		t.Errorf("got deflate=%v client=%v server=%v", d, c, s)
	}
}

// ---- persistent CA ----

func TestCA_PersistsAcrossRuns(t *testing.T) {
	savedCert, savedKey := caCert, caKey
	defer func() { caCert, caKey = savedCert, savedKey; resetCertCache() }()

	dir := filepath.Join(t.TempDir(), "ca")
	path, created, err := loadOrCreateCA(dir)
	if err != nil || !created {
		t.Fatalf("first use: created=%v err=%v", created, err)
	}
	first := caCert
	// Windows has no Unix permission bits; the key is private by its ACL.
	if fi, _ := os.Stat(filepath.Join(dir, caKeyFile)); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", fi.Mode().Perm())
	}

	caCert = nil
	if _, created, err := loadOrCreateCA(dir); err != nil || created {
		t.Fatalf("second use: created=%v err=%v", created, err)
	}
	if !caCert.Equal(first) {
		t.Error("second run loaded a different CA")
	}
	leaf, err := generateCert("persist.example")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := parseLeaf(leaf)
	if err := cert.CheckSignatureFrom(first); err != nil {
		t.Errorf("leaf not signed by the persisted CA: %v", err)
	}
	if !strings.HasSuffix(path, caCertFile) {
		t.Errorf("path = %q", path)
	}

	// Half a CA is refused rather than silently replaced.
	os.Remove(filepath.Join(dir, caKeyFile)) //nolint:errcheck
	if _, _, err := loadOrCreateCA(dir); err == nil {
		t.Error("a directory with only the certificate was accepted")
	}
}

// ---- JVM ----

func TestJavaTrustStore_HoldsTheProxyCA(t *testing.T) {
	bundle, err := buildCABundle(caPEM())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(bundle)
	ts, err := buildJavaTrustStore(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(ts)
	data, _ := os.ReadFile(ts)
	certs, err := pkcs12.DecodeTrustStore(data, javaTrustStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range certs {
		if c.Equal(caCert) {
			found = true
		}
	}
	if !found {
		t.Errorf("truststore (%d certs) lacks httpmon's CA", len(certs))
	}
}

func TestJavaToolOptions_AppendsAfterInherited(t *testing.T) {
	got := javaToolOptions("-Xmx1g -Dhttps.proxyHost=corp", "127.0.0.1", "4321", "/tmp/ts.p12")
	if !strings.HasPrefix(got, "-Xmx1g -Dhttps.proxyHost=corp ") {
		t.Errorf("inherited options not kept first: %q", got)
	}
	// The JVM applies the last definition, so httpmon's must come after.
	if strings.LastIndex(got, "-Dhttps.proxyHost=127.0.0.1") < strings.Index(got, "-Dhttps.proxyHost=corp") {
		t.Errorf("httpmon's proxy does not override the inherited one: %q", got)
	}
	for _, want := range []string{"-Dhttps.proxyPort=4321", "-Djavax.net.ssl.trustStore=/tmp/ts.p12", "-Dhttp.nonProxyHosts="} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %q", want, got)
		}
	}
}

// ---- curl ----

func TestCurlArgs(t *testing.T) {
	const px, ca = "http://127.0.0.1:9", "/tmp/ca.pem"
	for _, tc := range []struct {
		in        []string
		wantProxy bool // httpmon adds -x
		wantCA    bool // httpmon adds --cacert
	}{
		{[]string{"curl", "https://x"}, true, true},
		{[]string{"curl", "--proxy=http://other", "https://x"}, false, true},
		{[]string{"curl", "-sx", "http://other", "https://x"}, false, true},
		{[]string{"curl", "-xhttp://other", "https://x"}, false, true},
		{[]string{"curl", "-sk", "https://x"}, true, false},
		// -H's value contains an x; it is not -x.
		{[]string{"curl", "-H", "x-foo: 1", "https://x"}, true, true},
		{[]string{"curl", "-Hx-foo: 1", "https://x"}, true, true},
	} {
		out, err := curlArgs(tc.in, px, ca)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(out, " ")
		if got := strings.Contains(joined, "-x "+px); got != tc.wantProxy {
			t.Errorf("%q: adds proxy = %v, want %v (%q)", tc.in, got, tc.wantProxy, joined)
		}
		if got := strings.Contains(joined, "--cacert "+ca); got != tc.wantCA {
			t.Errorf("%q: adds CA = %v, want %v (%q)", tc.in, got, tc.wantCA, joined)
		}
	}
}

// A user's own --cacert is merged with httpmon's CA instead of being left to
// fail against httpmon's certificates.
func TestCurlArgs_MergesUserCACert(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user.pem")
	ours := filepath.Join(dir, "ours.pem")
	os.WriteFile(user, []byte("USER-CA\n"), 0o600) //nolint:errcheck
	os.WriteFile(ours, []byte("OUR-CA\n"), 0o600)  //nolint:errcheck
	defer runCleanups()

	for _, args := range [][]string{
		{"curl", "--cacert", user, "https://x"},
		{"curl", "--cacert=" + user, "https://x"},
	} {
		out, err := curlArgs(args, "http://p", ours)
		if err != nil {
			t.Fatal(err)
		}
		var merged string
		for i, a := range out {
			if a == "--cacert" {
				merged = out[i+1]
			} else if strings.HasPrefix(a, "--cacert=") {
				merged = strings.TrimPrefix(a, "--cacert=")
			}
		}
		data, _ := os.ReadFile(merged)
		if !bytes.Contains(data, []byte("USER-CA")) || !bytes.Contains(data, []byte("OUR-CA")) {
			t.Errorf("%q: --cacert %s holds %q, want both CAs", args, merged, data)
		}
	}
}

// ---- TUI ----

func TestTUI_SearchFiltersEntries(t *testing.T) {
	m := newTestModel(t, 100, 40)
	for i, p := range []string{"/users", "/orders", "/users/7"} {
		m = send(t, m, tuiReqMsg{&tuiEntry{id: i + 1, method: "GET", host: "api", path: p, rawURL: "https://api" + p, pending: true}})
	}
	m = send(t, m, key("/"))
	for _, r := range "users" {
		m = send(t, m, key(string(r)))
	}
	m = send(t, m, tea_enter())
	if n := len(m.visible()); n != 2 {
		t.Fatalf("search matched %d entries, want 2", n)
	}
	if v := m.View(); !strings.Contains(v, "2 of 3 requests") {
		t.Errorf("header does not show the match count:\n%s", v)
	}
	m = send(t, m, tea_esc())
	if n := len(m.visible()); n != 3 {
		t.Errorf("esc did not clear the search: %d visible", n)
	}
}

func TestTUI_EntriesAreBounded(t *testing.T) {
	m := newTestModel(t, 100, 40)
	for i := 1; i <= maxTUIEntries+10; i++ {
		m = send(t, m, tuiReqMsg{&tuiEntry{id: i, method: "GET", host: "h", path: "/"}})
	}
	if len(m.entries) != maxTUIEntries || m.entries[0].id != 11 {
		t.Errorf("entries = %d starting at #%d, want %d starting at #11", len(m.entries), m.entries[0].id, maxTUIEntries)
	}
	if len(m.byID) != maxTUIEntries {
		t.Errorf("index holds %d entries", len(m.byID))
	}
}

func TestCurlCommand(t *testing.T) {
	e := &tuiEntry{
		method: "POST", curlURL: "https://api.example.com/v1?q=a b",
		rawReqHeaders: http.Header{"Authorization": {"Bearer t'ok"}, "Content-Length": {"5"}},
		reqBodyRaw:    []byte(`{"a":1}`), reqBodyWhole: true,
	}
	got := curlCommand(e)
	for _, want := range []string{"curl -X POST", `'https://api.example.com/v1?q=a b'`, `-H 'Authorization: Bearer t'\''ok'`, `--data-binary '{"a":1}'`} {
		if !strings.Contains(got, want) {
			t.Errorf("curl command lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Content-Length") {
		t.Errorf("Content-Length should be left to curl:\n%s", got)
	}
}

// ---- end to end: output channel ----

// httpmon's output goes to stderr, so the wrapped command's stdout is exactly
// what the command wrote and can be piped.
func TestBinary_OutputLeavesStdoutToTheCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"from":"upstream"}`) //nolint:errcheck
	}))
	defer upstream.Close()

	bin := filepath.Join(t.TempDir(), "httpmon"+exeSuffix)
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, format := range []string{"text", "json"} {
		cmd := exec.Command(bin, "--format", format, "curl", "-s", upstream.URL+"/")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s: %v\n%s", format, err, stderr.String())
		}
		if stdout.String() != `{"from":"upstream"}` {
			t.Errorf("%s: stdout = %q, want only curl's output", format, stdout.String())
		}
		if e := stderr.String(); !strings.Contains(e, `"id":1`) && !strings.Contains(e, "RESPONSE #1") {
			t.Errorf("%s: stderr lacks httpmon's output:\n%s", format, stderr.String())
		}
	}

	// -o writes to a file instead.
	outFile := filepath.Join(t.TempDir(), "trace.ndjson")
	cmd := exec.Command(bin, "--format", "json", "-o", outFile, "curl", "-s", upstream.URL+"/")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("-o: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(outFile)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("-o file has a non-JSON line: %q", line)
		}
	}
	if !bytes.Contains(data, []byte(`"id":1`)) {
		t.Errorf("-o file lacks the response:\n%s", data)
	}
}

func tea_enter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func tea_esc() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyEsc} }
