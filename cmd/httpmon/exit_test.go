package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
)

// Regression: the wrapped command can hold the whole response -- its
// Content-Length satisfied -- while httpmon still waits for the upstream's
// end-of-stream, which an HTTP/2 upstream sends separately. If the command
// exited in that gap, httpmon exited too and the exchange never reached the
// HAR or the recording. Measured: 1 in 30 single-request runs lost it.
func TestExit_DrainWaitsForFinalExchange(t *testing.T) {
	const payload = "complete-body"
	upstream := newH2TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		io.WriteString(w, payload) //nolint:errcheck
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond) // end-of-stream arrives late
	}))
	defer upstream.Close()
	useInsecureUpstream(t)

	mem := useMemoryHAR(t)

	client, cleanup := proxiedClient(t) // HTTP/1.1 to httpmon, HTTP/2 upstream
	defer cleanup()
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if string(body) != payload {
		t.Fatalf("body = %q", body)
	}

	early := len(mem.entries())
	if early != 0 {
		t.Skip("the exchange completed before the client did; the race was not exercised")
	}

	drainInflight(3 * time.Second)

	if n := len(mem.entries()); n != 1 {
		t.Errorf("HAR has %d entries after draining, want 1", n)
	}
}

// connectThrough opens a CONNECT tunnel through httpmon and returns it once
// the 200 has been read.
func connectThrough(t *testing.T, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", startTestProxy(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })                 //nolint:errcheck
	c.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	return c, br
}

// Regression: a protocol where the server speaks first (SMTP, SSH, MySQL)
// deadlocked -- the client waited for the banner, httpmon waited for the
// client -- and the connection timed out.
func TestConnect_ServerFirstProtocolIsRelayed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "220 ready\r\n") //nolint:errcheck
		line, _ := bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, "250 "+line) //nolint:errcheck
	}()

	c, br := connectThrough(t, ln.Addr().String())
	banner, err := br.ReadString('\n')
	if err != nil || banner != "220 ready\r\n" {
		t.Fatalf("banner = %q, %v", banner, err)
	}
	io.WriteString(c, "EHLO me\r\n") //nolint:errcheck
	reply, err := br.ReadString('\n')
	if err != nil || reply != "250 EHLO me\r\n" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
}

// A client-first protocol that is neither TLS nor HTTP (Redis, Postgres,
// MQTT…) was handed to the HTTP server, which answered 400 and hung up.
func TestConnect_NonHTTPClientProtocolIsRelayed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c) //nolint:errcheck
	}()

	c, br := connectThrough(t, ln.Addr().String())
	io.WriteString(c, "*1\r\n$4\r\nPING\r\n") //nolint:errcheck
	got := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "*1\r\n$4\r\nPING\r\n" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

// A v3 record keeps a gRPC call's bytes, so replay re-sends it and compares
// its grpc-status as well as the body.
func TestReplay_GRPCCallFromRecord(t *testing.T) {
	var got [][]byte
	target := newH2TLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, b)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(grpcFrame([]byte("reply"))) //nolint:errcheck
		w.Header().Set("Grpc-Status", "0")
	}))
	defer target.Close()
	useInsecureUpstream(t)
	saved := insecureUpstream
	insecureUpstream = true
	defer func() { insecureUpstream = saved }()

	reqFrame := grpcFrame([]byte("request"))
	e := &exchange.Exchange{
		V: 3, Session: "s", ID: 1, Kind: "http", Method: "POST", URL: target.URL + "/pkg.Svc/Call", Status: 200,
		Request: exchange.Message{
			Headers: exchange.Headers{"Content-Type": {"application/grpc"}, "Te": {"trailers"}},
			Body:    &body.Rendered{Size: int64(len(reqFrame)), Raw: body.NewRaw(reqFrame, false)},
		},
		Response: &exchange.Message{
			Headers:  exchange.Headers{"Content-Type": {"application/grpc"}},
			Trailers: exchange.Headers{"Grpc-Status": {"0"}},
			Body:     &body.Rendered{Size: 10, Raw: body.NewRaw(grpcFrame([]byte("reply")), false)},
		},
	}
	path := filepath.Join(t.TempDir(), "grpc.ndjson")
	data, _ := json.Marshal(e)
	os.WriteFile(path, append(data, '\n'), 0o600) //nolint:errcheck

	out := captureText(t)
	if code := replayFile(path, "", 0, true); code != 0 {
		t.Fatalf("exit = %d, want 0; output:\n%s", code, out.String())
	}
	if len(got) != 1 || !bytes.Equal(got[0], reqFrame) {
		t.Errorf("server received %q, want the recorded frame", got)
	}
	if !strings.Contains(out.String(), "gRPC:    recorded=0  actual=0") {
		t.Errorf("gRPC status not compared; output:\n%s", out.String())
	}
}
