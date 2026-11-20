package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hxddh/https-traffic-inspector/v5/internal/body"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v5/internal/session"
	"github.com/hxddh/https-traffic-inspector/v5/internal/store"
)

func TestV5_HTTPSTraceConnReuseAndHAR(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		io.WriteString(w, `{"ok":true}`) //nolint:errcheck
	}))
	defer up.Close()

	savedInsecure, savedClient := insecureUpstream, upstreamClient
	insecureUpstream = true
	upstreamClient = newUpstreamClient(true)
	defer func() {
		insecureUpstream, upstreamClient = savedInsecure, savedClient
	}()

	dir := filepath.Join(t.TempDir(), "s")
	captureText(t)
	useStats(t, "")
	useSession(t, dir, false)

	proxyAddr := startTestProxy(t)
	pu, _ := url.Parse("http://" + proxyAddr)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	c := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}

	for range 2 {
		resp, err := c.Get(up.URL + "/ping")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
	drainInflight(2 * time.Second)

	st, err := store.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if len(st.Entries) != 2 {
		t.Fatalf("recorded %d exchanges, want 2", len(st.Entries))
	}
	e1, _ := st.Read(st.Entries[0])
	e2, _ := st.Read(st.Entries[1])
	if e1.V != 4 || e1.Timings == nil || e1.Conn == nil {
		t.Fatalf("e1 missing v4 timings/conn: %+v", e1)
	}
	if e1.Conn.Reused || !e2.Conn.Reused || e1.Conn.TLSVersion == "" || e1.Conn.CertDaysLeft == nil {
		t.Errorf("conn1=%+v conn2=%+v", e1.Conn, e2.Conn)
	}
	if e1.Timings.RecvMs < 15 {
		t.Errorf("timings = %+v, want recv >= 15ms", e1.Timings)
	}

	harRaw, code := runQuery(t, dir, "--format", "har")
	if code != 0 {
		t.Fatalf("har exit %d", code)
	}
	var hf harFile
	if err := json.Unmarshal([]byte(harRaw), &hf); err != nil {
		t.Fatal(err)
	}
	if hf.Log.Entries[0].Timings.Receive <= 0 || hf.Log.Entries[0].ServerIPAddress == "" {
		t.Errorf("HAR entry = %+v", hf.Log.Entries[0])
	}
}

func TestV5_SSESoftErrorAndFailOnAppError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\"}}\n\n") //nolint:errcheck
			for i := range 30 {
				fmt.Fprintf(w, "event: content_block_delta\ndata: {\"delta\":{\"text\":\"chunk_%d \"}}\n\n", i)
			}
			io.WriteString(w, "event: error\ndata: {\"type\":\"error\",\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"Quota\"}}\n\n") //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"UNAUTHENTICATED"}}]}`) //nolint:errcheck
	}))
	defer up.Close()

	dir := filepath.Join(t.TempDir(), "s")
	out := useSummary(t)
	useStats(t, "app_error")
	useSession(t, dir, false)

	c := proxyClient(t)
	for _, p := range []string{"/sse", "/graphql"} {
		resp, err := c.Get(up.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
	drainInflight(2 * time.Second)
	if code := finishRun(0); code != exitFailOn {
		t.Errorf("finishRun = %d, want %d on app_error", code, exitFailOn)
	}
	sum := out.String()
	if !strings.Contains(sum, "200 sse") || !strings.Contains(sum, "ERR rate_limit_exceeded") || !strings.Contains(sum, "200 graphql ERR UNAUTHENTICATED") {
		t.Errorf("summary:\n%s", sum)
	}

	// query --diagnose surfaces both soft errors.
	diagOut, code := runQuery(t, dir, "--diagnose")
	if code != 0 || !strings.Contains(diagOut, "Protocol soft errors") || !strings.Contains(diagOut, "rate_limit_exceeded") {
		t.Errorf("query --diagnose (exit %d):\n%s", code, diagOut)
	}
}

func TestV5_ClientTLSRejectedAndOpaqueTunnelRecorded(t *testing.T) {
	// Raw TCP echo server (speaks first -> opaque non-HTTP tunnel).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("220 echo\r\n")) //nolint:errcheck
		buf := make([]byte, 4)
		io.ReadFull(conn, buf) //nolint:errcheck
	}()

	dir := filepath.Join(t.TempDir(), "s")
	captureText(t)
	useStats(t, "error")
	useSession(t, dir, false)
	proxyAddr := startTestProxy(t)

	// 1. Client connects via CONNECT and rejects httpmon's certificate (uses empty RootCAs).
	c1, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c1, "CONNECT untrusted.example:443 HTTP/1.1\r\nHost: untrusted.example:443\r\n\r\n")
	br1 := bufio.NewReader(c1)
	http.ReadResponse(br1, &http.Request{Method: "CONNECT"}) //nolint:errcheck
	tc := tls.Client(c1, &tls.Config{ServerName: "untrusted.example"})
	_ = tc.Handshake() // expected to fail: httpmon's ephemeral CA is not in system roots
	c1.Close()

	// 2. Client opens a non-HTTP CONNECT tunnel to the raw TCP server.
	c2, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	target := ln.Addr().String()
	fmt.Fprintf(c2, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br2 := bufio.NewReader(c2)
	http.ReadResponse(br2, &http.Request{Method: "CONNECT"}) //nolint:errcheck
	banner := make([]byte, 10)
	io.ReadFull(br2, banner) //nolint:errcheck
	c2.Write([]byte("QUIT")) //nolint:errcheck
	c2.Close()

	// Wait briefly for server-side handlers to record both tunnel events.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := store.Open(dir, false)
		if err == nil {
			n := len(st.Entries)
			st.Close()
			if n >= 2 {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}

	out, code := runQuery(t, dir)
	if code != 0 || !strings.Contains(out, "ERR client_tls_untrusted") || !strings.Contains(out, "→ tunnel (") {
		t.Errorf("query tunnel session (exit %d):\n%s", code, out)
	}
	if exit := finishRun(0); exit != exitFailOn {
		t.Errorf("finishRun = %d, want %d on client_tls_untrusted", exit, exitFailOn)
	}
}

func TestV5_MCPNonBlockingCancelIsolationAndDiagnose(t *testing.T) {
	api := apiServer(t)
	dir := filepath.Join(t.TempDir(), "s")
	captureText(t)
	useStats(t, "")
	useSession(t, dir, false)
	get(t, api.URL+"/items")
	get(t, api.URL+"/fail")
	drainInflight(2 * time.Second)

	// 1. Concurrent wait_for_exchange must not block ping, and honours notifications/cancelled.
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan struct{})
	go func() {
		serveMCP(inR, outW, mcpTools(false))
		outW.Close()
		close(done)
	}()

	sc := bufio.NewScanner(outR)
	writeLine := func(s string) {
		io.WriteString(inW, s+"\n") //nolint:errcheck
	}
	readResp := func() map[string]any {
		if !sc.Scan() {
			t.Fatal("unexpected EOF from MCP server")
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// Start a 30s wait (id 10), then immediately send ping (id 11): ping must arrive first and fast.
	t0 := time.Now()
	writeLine(fmt.Sprintf(`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"wait_for_exchange","arguments":{"session":%q,"url":"/never","timeout_sec":30}}}`, dir))
	writeLine(`{"jsonrpc":"2.0","id":11,"method":"ping"}`)
	rPing := readResp()
	if rPing["id"].(float64) != 11 || time.Since(t0) > 2*time.Second {
		t.Fatalf("ping blocked behind wait_for_exchange: %v (%v)", rPing, time.Since(t0))
	}
	// Cancel request 10 via notifications/cancelled: wait_for_exchange must return immediately.
	writeLine(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":10}}`)
	rWait := readResp()
	if rWait["id"].(float64) != 10 || time.Since(t0) > 3*time.Second {
		t.Fatalf("cancelled wait_for_exchange did not return promptly: %v (%v)", rWait, time.Since(t0))
	}

	// 2. max_body in get_exchange must not leak to subsequent calls; diagnose_session works.
	savedMax := displayMaxBody
	displayMaxBody = 4000
	defer func() { displayMaxBody = savedMax }()
	writeLine(fmt.Sprintf(`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"get_exchange","arguments":{"session":%q,"id":2,"max_body":15}}}`, dir))
	_ = readResp()
	if displayMaxBody != 4000 {
		t.Errorf("mcpGetExchange mutated global displayMaxBody to %d", displayMaxBody)
	}
	writeLine(fmt.Sprintf(`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"diagnose_session","arguments":{"session":%q}}}`, dir))
	rDiag := readResp()
	if txt, isErr := toolText(t, rDiag); isErr || !strings.Contains(txt, "db_timeout") {
		t.Errorf("diagnose_session: %s", txt)
	}

	inW.Close()
	<-done
}

func TestV5_StaleHeartbeatAllowsSessionRemoval(t *testing.T) {
	t.Setenv("HTTPMON_HOME", t.TempDir())
	d, _ := session.Dir("crashed")
	session.Create(d, false) //nolint:errcheck
	// PID is alive (our own process), as PID 1 is in a restarted container,
	// but live.json has not been updated for 10 minutes.
	old := time.Now().Add(-10 * time.Minute)
	session.WriteJSON(d, session.MetaFile, session.Meta{Name: "crashed", PID: os.Getpid(), Started: old}) //nolint:errcheck
	session.WriteJSON(d, session.LiveFile, session.Live{PID: os.Getpid(), Updated: old})                  //nolint:errcheck

	if err := session.Remove("crashed"); err != nil {
		t.Fatalf("stale session could not be removed: %v", err)
	}
}

func TestV5_SchemaCoversEveryExchangeField(t *testing.T) {
	var sch map[string]any
	if err := json.Unmarshal([]byte(exchangeSchema), &sch); err != nil {
		t.Fatal(err)
	}
	props := sch["properties"].(map[string]any)
	checkStruct := func(typ reflect.Type, schemaProps map[string]any) {
		for i := range typ.NumField() {
			tag := typ.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if name == "" {
				continue
			}
			if _, ok := schemaProps[name]; !ok {
				t.Errorf("JSON field %s.%s (%q) is missing from httpmon schema", typ.Name(), typ.Field(i).Name, name)
			}
		}
	}
	checkStruct(reflect.TypeFor[exchange.Exchange](), props)
	defs := sch["$defs"].(map[string]any)
	checkStruct(reflect.TypeFor[exchange.Message](), defs["message"].(map[string]any)["properties"].(map[string]any))
	checkStruct(reflect.TypeFor[body.Rendered](), defs["body"].(map[string]any)["properties"].(map[string]any))
	checkStruct(reflect.TypeFor[exchange.Timings](), props["timings"].(map[string]any)["properties"].(map[string]any))
	checkStruct(reflect.TypeFor[exchange.ConnInfo](), props["conn"].(map[string]any)["properties"].(map[string]any))
	checkStruct(reflect.TypeFor[exchange.SemanticMeta](), props["meta"].(map[string]any)["properties"].(map[string]any))
	checkStruct(reflect.TypeFor[exchange.CausalLink](), props["cause"].(map[string]any)["properties"].(map[string]any))
	checkStruct(reflect.TypeFor[exchange.TunnelInfo](), props["tunnel"].(map[string]any)["properties"].(map[string]any))
}

func TestSummaryMode_LongSSEErrorBeyondCaptureLimit(t *testing.T) {
	savedCap := captureMaxBody
	captureMaxBody = 16 << 10
	defer func() { captureMaxBody = savedCap }()

	out := useSummary(t)
	useStats(t, "app_error")

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// Emit >100 KiB of normal deltas (well past both 16 KiB captureMaxBody and 64 KiB)
		// followed by a trailing SSE error event with no standard "message" field.
		io.WriteString(w, "event: message_start\ndata: {\"message\":{\"model\":\"claude-sonnet-4-6\"}}\n\n") //nolint:errcheck
		chunk := "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"" + strings.Repeat("x", 512) + "\"}}\n\n"
		for range 200 {
			io.WriteString(w, chunk) //nolint:errcheck
		}
		io.WriteString(w, "event: error\ndata: {\"reason\":\"overloaded\"}\n\n") //nolint:errcheck
	}))
	defer up.Close()

	c := proxyClient(t)
	resp, err := c.Get(up.URL + "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	drainInflight(2 * time.Second)

	if code := finishRun(0); code != exitFailOn {
		t.Fatalf("finishRun = %d, want %d on trailing SSE app_error; summary:\n%s", code, exitFailOn, out.String())
	}
	if !strings.Contains(out.String(), "overloaded") {
		t.Errorf("summary output missing overloaded hint:\n%s", out.String())
	}
}
