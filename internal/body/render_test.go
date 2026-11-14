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
