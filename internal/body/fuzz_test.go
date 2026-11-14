package body

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"testing"
	"unicode/utf8"
)

// FuzzRender: any body, under any declared type and encoding, renders
// without panicking, within its budget, and to valid JSON.
func FuzzRender(f *testing.F) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(`{"a":[1,2,{"b":"c"}]}`)) //nolint:errcheck
	w.Close()
	f.Add([]byte(`{"error":{"code":"x"}}`), "application/json", "", false)
	f.Add(gz.Bytes(), "application/json", "gzip", true)
	f.Add([]byte{0, 0, 0, 0, 3, 8, 150, 1}, "application/grpc", "", false)
	f.Add([]byte("plain\x1b[31m text"), "text/plain", "", false)
	f.Add([]byte{0xff, 0xfe, 0}, "", "br, gzip", true)
	f.Fuzz(func(t *testing.T, raw []byte, ct, ce string, truncated bool) {
		h := http.Header{}
		h.Set("Content-Type", ct)
		h.Set("Content-Encoding", ce)
		r, _ := Render(h, raw, truncated, int64(len(raw)), 200)
		if r == nil {
			if len(raw) > 0 {
				t.Fatal("nil rendering of a non-empty body")
			}
			return
		}
		if r.Text != nil && !utf8.ValidString(*r.Text) {
			t.Errorf("text is not UTF-8: %q", *r.Text)
		}
		if _, err := json.Marshal(r); err != nil {
			t.Errorf("rendering does not marshal: %v", err)
		}
	})
}

// FuzzDecodeProtobuf: schema-less decoding never panics or recurses away.
func FuzzDecodeProtobuf(f *testing.F) {
	f.Add([]byte{8, 150, 1, 18, 3, 'a', 'b', 'c'})
	f.Add([]byte{10, 2, 8, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if o, err := DecodeProtobuf(b); err == nil {
			if _, err := json.Marshal(o); err != nil {
				t.Errorf("decoded message does not marshal: %v", err)
			}
		}
	})
}
