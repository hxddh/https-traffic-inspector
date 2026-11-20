package body

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestParseJSON_KeepsOrderAndNumbers(t *testing.T) {
	v, err := ParseJSON([]byte(`{"z":1,"a":{"y":12345678901234567890,"b":[true,null,"s"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(v)
	if string(out) != `{"z":1,"a":{"y":12345678901234567890,"b":[true,null,"s"]}}` {
		t.Errorf("round trip = %s", out)
	}
	if _, err := ParseJSON([]byte(`{"a":1} trailing`)); err == nil {
		t.Error("trailing data accepted")
	}
}

// Regression: v2 cut a JSON body at --max-body bytes and appended a marker
// inside the string, so the body no longer parsed. Truncation now keeps the
// structure, and the result is always valid JSON.
func TestTruncateJSON_StaysValidAndSaysWhatItCut(t *testing.T) {
	var items []string
	for i := 0; i < 40; i++ {
		items = append(items, fmt.Sprintf(`{"id":%d,"description":"%s"}`, i, strings.Repeat("lorem ipsum ", 10)))
	}
	src := `{"items":[` + strings.Join(items, ",") + `],"next":"/items?page=2"}`
	v, _ := ParseJSON([]byte(src))

	out, cut := TruncateJSON(v, 1000)
	if !cut {
		t.Fatal("a 5 KB body was not cut to a 1000-byte budget")
	}
	b, _ := json.Marshal(out)
	if !json.Valid(b) {
		t.Fatalf("truncated JSON is invalid: %s", b)
	}
	if len(b) > 1000 {
		t.Errorf("truncated to %d bytes, budget 1000", len(b))
	}
	for _, want := range []string{`"next":"/items?page=2"`, "more items", `"id":0`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("truncated JSON lacks %s: %s", want, b)
		}
	}

	small, cut := TruncateJSON(v, 1<<20)
	if cut {
		t.Error("a body within budget was cut")
	}
	if b2, _ := json.Marshal(small); string(b2) != string(must(json.Marshal(v))) {
		t.Error("a body within budget was changed")
	}
}

func must(b []byte, _ error) []byte { return b }

func TestErrorHint(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"error":{"code":"db_timeout","message":"slow"}}`, "db_timeout"},
		{`{"error":"invalid_grant","error_description":"expired"}`, "invalid_grant"},
		{`{"message":"Not Found","documentation_url":"…"}`, "Not Found"},
		{`{"errors":[{"code":"E42","message":"bad"}]}`, "E42"},
		{`{"detail":"Authentication credentials were not provided."}`, "Authentication credentials were not provided."},
		{`{"ok":false}`, ""},
	} {
		v, _ := ParseJSON([]byte(tc.in))
		if got := ErrorHint(v); got != tc.want {
			t.Errorf("ErrorHint(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDecodeProtobuf(t *testing.T) {
	// field 1: varint 150; field 2: "testing"; field 3: nested {1: 7};
	// field 4 twice: repeated varints.
	msg := []byte{0x08, 0x96, 0x01, 0x12, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g', 0x1a, 0x02, 0x08, 0x07, 0x20, 0x01, 0x20, 0x02}
	obj, err := DecodeProtobuf(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(obj)
	if string(got) != `{"1":150,"2":"testing","3":{"1":7},"4":[1,2]}` {
		t.Errorf("decoded = %s", got)
	}
	if _, err := DecodeProtobuf([]byte{0x0b}); err == nil { // wire type 3 (groups)
		t.Error("unsupported wire type accepted")
	}
}

func TestRender(t *testing.T) {
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(s)) //nolint:errcheck
		w.Close()
		return b.Bytes()
	}
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}

	r, hint := Render(h("Content-Type", "application/json", "Content-Encoding", "gzip"), gz(`{"error":{"code":"E1"}}`), false, 40, 1000)
	if r.JSON == nil || hint != "E1" || r.Size != 40 {
		t.Errorf("gzip JSON: %+v hint %q", r, hint)
	}

	r, _ = Render(h("Content-Type", "text/plain"), []byte("hello"), false, 5, 1000)
	if r.Text == nil || *r.Text != "hello" {
		t.Errorf("text: %+v", r)
	}

	r, _ = Render(h("Content-Type", "text/plain"), []byte(strings.Repeat("x", 50)), false, 50, 10)
	if r.Text == nil || len(*r.Text) != 10 || !r.Truncated {
		t.Errorf("text over budget: %+v", r)
	}

	r, _ = Render(h("Content-Type", "application/octet-stream"), []byte{0, 1, 2}, false, 3, 1000)
	if !r.Binary || r.Text != nil {
		t.Errorf("binary: %+v", r)
	}

	// A JSON body cut at capture time cannot be parsed; it is shown as text.
	r, _ = Render(h("Content-Type", "application/json"), []byte(`{"a":[1,2`), true, 100, 1000)
	if r.Text == nil || !r.Truncated {
		t.Errorf("partial JSON: %+v", r)
	}

	frame := append([]byte{0, 0, 0, 0, 2}, 0x08, 0x05)
	r, _ = Render(h("Content-Type", "application/grpc"), frame, false, 7, 1000)
	if len(r.GRPC) != 1 || r.GRPC[0].Fields == nil {
		t.Errorf("gRPC: %+v", r)
	}

	if r, _ := Render(h(), nil, false, 0, 1000); r != nil {
		t.Errorf("empty body rendered as %+v", r)
	}
}

func TestDecompressLimit_StopsEarly(t *testing.T) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(bytes.Repeat([]byte("a"), 1<<20)) //nolint:errcheck
	w.Close()
	res, err := DecompressLimit("gzip", b.Bytes(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Data) != 100 || !res.Truncated {
		t.Errorf("decoded %d bytes (truncated=%v), want 100 and truncated", len(res.Data), res.Truncated)
	}
}

func TestRaw_RoundTrip(t *testing.T) {
	for _, in := range [][]byte{[]byte("text"), {0xff, 0x00, 0x9b}} {
		r := NewRaw(in, false)
		out, err := r.Bytes()
		if err != nil || !bytes.Equal(out, in) {
			t.Errorf("%q → %+v → %q (%v)", in, r, out, err)
		}
	}
}

// Regression: Object had no UnmarshalJSON, so a record holding decoded gRPC
// fields could not be read back by query or replay.
func TestRendered_GRPCRoundTrips(t *testing.T) {
	msgs, _ := DecodeGRPC(append([]byte{0, 0, 0, 0, 2}, 0x08, 0x05))
	b, err := json.Marshal(Rendered{Size: 7, GRPC: msgs})
	if err != nil {
		t.Fatal(err)
	}
	var back Rendered
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("cannot read back %s: %v", b, err)
	}
	if v, _ := back.GRPC[0].Fields.Get("1"); v == nil {
		t.Errorf("fields lost: %+v", back.GRPC[0].Fields)
	}
}

// Regression: the budget only dropped whole messages, so a single large
// message was rendered in full and not marked truncated.
func TestRender_BoundsALargeGRPCMessage(t *testing.T) {
	big := strings.Repeat("x", 10000)
	pb := append([]byte{0x0a, 0x90, 0x4e}, big...) // field 1, length 10000 (varint 0x90 0x4e)
	frame := append([]byte{0, 0, 0, byte(len(pb) >> 8), byte(len(pb))}, pb...)
	r, _ := Render(http.Header{"Content-Type": {"application/grpc"}}, frame, false, int64(len(frame)), 100)
	b, _ := json.Marshal(r.GRPC)
	if len(b) > 400 || !r.Truncated {
		t.Errorf("rendered %d bytes, truncated=%v; want it within budget and marked", len(b), r.Truncated)
	}
}

func TestRender_SSEAndLLMAssembly(t *testing.T) {
	var sse strings.Builder
	sse.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":42}}}\n\n")
	sse.WriteString("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"read_file\"}}\n\n")
	for i := range 40 {
		fmt.Fprintf(&sse, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"tok%d \"}}\n\n", i)
	}
	sse.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":99}}\n\n")
	sse.WriteString("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n")

	h := http.Header{"Content-Type": {"text/event-stream; charset=utf-8"}}
	r, hint := Render(h, []byte(sse.String()), false, int64(sse.Len()), 600)
	if r == nil || r.Stream == nil {
		t.Fatalf("expected StreamInfo, got %+v", r)
	}
	st := r.Stream
	if st.Format != "sse" || st.Events != 44 || st.Model != "claude-sonnet-4-6" || st.StopReason != "end_turn" {
		t.Errorf("stream = %+v", st)
	}
	if !strings.HasPrefix(st.Assembled, "tok0 tok1 ") || len(st.ToolCalls) != 1 || st.ToolCalls[0] != "read_file" {
		t.Errorf("assembled=%q tools=%v", st.Assembled, st.ToolCalls)
	}
	if st.Usage["input_tokens"] != 42 || st.Usage["output_tokens"] != 99 {
		t.Errorf("usage = %v", st.Usage)
	}
	if st.Error != "overloaded_error" || hint != "overloaded_error" || r.SoftErrorKind != "sse" {
		t.Errorf("error=%q hint=%q soft=%q", st.Error, hint, r.SoftErrorKind)
	}
	if len(st.Tail) == 0 || st.Omitted == 0 {
		t.Errorf("expected head+tail windowing, got head=%d tail=%d omitted=%d", len(st.Head), len(st.Tail), st.Omitted)
	}
}

func TestRender_MultipartAndSoftErrors(t *testing.T) {
	mp := "--bnd\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"role\":\"admin\"}\r\n" +
		"--bnd\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\x01\x02\r\n--bnd--\r\n"
	r, _ := Render(http.Header{"Content-Type": {"multipart/form-data; boundary=bnd"}}, []byte(mp), false, int64(len(mp)), 1000)
	if r == nil || len(r.Parts) != 2 {
		t.Fatalf("parts = %+v", r)
	}
	if r.Parts[0].Name != "meta" || r.Parts[0].Value != `{"role":"admin"}` || !r.Parts[1].Binary || r.Parts[1].Filename != "a.png" {
		t.Errorf("parts = %+v", r.Parts)
	}

	gqlReq, _ := Render(http.Header{"Content-Type": {"application/json"}}, []byte(`{"query":"mutation CreateOrder($x: ID!) { createOrder(id: $x) }"}`), false, 64, 1000)
	if gqlReq.GraphQLOp != "mutation CreateOrder" {
		t.Errorf("GraphQLOp = %q", gqlReq.GraphQLOp)
	}
	gqlResp, _ := Render(http.Header{"Content-Type": {"application/json"}}, []byte(`{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"UNAUTHENTICATED"}}]}`), false, 90, 1000)
	if gqlResp.SoftErrorKind != "graphql" || gqlResp.SoftErrorHint != "UNAUTHENTICATED" {
		t.Errorf("graphql soft error = %q %q", gqlResp.SoftErrorKind, gqlResp.SoftErrorHint)
	}
	rpcResp, _ := Render(http.Header{"Content-Type": {"application/json"}}, []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`), false, 77, 1000)
	if rpcResp.SoftErrorKind != "jsonrpc" || rpcResp.SoftErrorHint != "-32601" {
		t.Errorf("jsonrpc soft error = %q %q", rpcResp.SoftErrorKind, rpcResp.SoftErrorHint)
	}
	_, truncHint := Render(http.Header{"Content-Type": {"application/json"}}, []byte(`{"error":{"code":"quota_exceeded","details":"`+strings.Repeat("a", 200)), true, 5000, 100)
	if truncHint != "quota_exceeded" {
		t.Errorf("truncated JSON error hint = %q, want quota_exceeded", truncHint)
	}

	sseFallback, _ := Render(http.Header{"Content-Type": {"text/event-stream"}}, []byte("event: error\ndata: {\"reason\":\"overloaded\"}\n\n"), false, 44, 1000)
	if sseFallback.SoftErrorKind != "sse" || sseFallback.SoftErrorHint != "overloaded" {
		t.Errorf("SSE fallback reason = %q %q, want sse/overloaded", sseFallback.SoftErrorKind, sseFallback.SoftErrorHint)
	}
	sseGeneric, _ := Render(http.Header{"Content-Type": {"text/event-stream"}}, []byte("event: error\ndata: {\"status\":529}\n\n"), false, 35, 1000)
	if sseGeneric.SoftErrorKind != "sse" || sseGeneric.SoftErrorHint == "" {
		t.Errorf("SSE fallback generic = %q %q, want non-empty sse error", sseGeneric.SoftErrorKind, sseGeneric.SoftErrorHint)
	}
}
