package body

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestDecompressBody_Gzip(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(`{"hello":"world"}`)) //nolint:errcheck
	w.Close()

	got, err := Decompress("gzip", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != `{"hello":"world"}` {
		t.Errorf("got %q", got.Data)
	}
	if got.Truncated {
		t.Error("did not expect Truncated for a complete stream")
	}
}

func TestDecompressBody_Deflate(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte("deflated text")) //nolint:errcheck
	w.Close()

	got, err := Decompress("deflate", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "deflated text" {
		t.Errorf("got %q", got.Data)
	}
}

// Servers commonly send zlib-wrapped data under "deflate" despite the raw
// deflate wording in older specs; both must decode.
func TestDecompressBody_DeflateZlibWrapped(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write([]byte("zlib wrapped")) //nolint:errcheck
	w.Close()

	got, err := Decompress("deflate", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "zlib wrapped" {
		t.Errorf("got %q", got.Data)
	}
}

func TestDecompressBody_Brotli(t *testing.T) {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	w.Write([]byte(`{"br":true}`)) //nolint:errcheck
	w.Close()

	got, err := Decompress("br", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != `{"br":true}` {
		t.Errorf("got %q", got.Data)
	}
}

func TestDecompressBody_Zstd(t *testing.T) {
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(`{"zstd":true}`)) //nolint:errcheck
	w.Close()

	got, err := Decompress("zstd", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != `{"zstd":true}` {
		t.Errorf("got %q", got.Data)
	}
}

// A Content-Encoding list is applied left to right, so it must be decoded
// right to left.
func TestDecompressBody_Chained(t *testing.T) {
	var inner bytes.Buffer
	gz := gzip.NewWriter(&inner)
	gz.Write([]byte("chained payload")) //nolint:errcheck
	gz.Close()

	var outer bytes.Buffer
	br := brotli.NewWriter(&outer)
	br.Write(inner.Bytes()) //nolint:errcheck
	br.Close()

	got, err := Decompress("gzip, br", outer.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "chained payload" {
		t.Errorf("got %q", got.Data)
	}
}

func TestDecompressBody_Identity(t *testing.T) {
	for _, enc := range []string{"", "identity", " identity "} {
		got, err := Decompress(enc, []byte("plain"))
		if err != nil {
			t.Fatalf("enc=%q: %v", enc, err)
		}
		if string(got.Data) != "plain" {
			t.Errorf("enc=%q: got %q", enc, got.Data)
		}
	}
}

// An encoding httpmon cannot decode must report an error rather than returning
// the still-compressed bytes, which callers would print as garbage.
func TestDecompressBody_UnknownReturnsError(t *testing.T) {
	_, err := Decompress("snappy", []byte("raw"))
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("got err=%v, want ErrUnsupportedEncoding", err)
	}
}

// Only a prefix of a large compressed body is captured, so decoding hits an
// unexpected EOF. The bytes decoded before that point are still useful.
func TestDecompressBody_TruncatedKeepsPrefix(t *testing.T) {
	payload := make([]byte, 4<<20)
	if _, err := crand.Read(payload); err != nil { // incompressible
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(payload) //nolint:errcheck
	zw.Close()
	if buf.Len() <= 1<<20 {
		t.Fatalf("compressed size %d too small to truncate", buf.Len())
	}

	got, err := Decompress("gzip", buf.Bytes()[:1<<20])
	if err != nil {
		t.Fatalf("truncated stream should not error: %v", err)
	}
	if !got.Truncated {
		t.Error("expected Truncated=true")
	}
	if len(got.Data) == 0 {
		t.Fatal("expected the successfully decoded prefix to be kept")
	}
	if !bytes.Equal(got.Data, payload[:len(got.Data)]) {
		t.Error("decoded prefix does not match the original payload")
	}
}

func TestGRPCSummary(t *testing.T) {
	two := append(grpcFrame([]byte("abc")), grpcFrame([]byte("de"))...)
	for _, tc := range []struct {
		raw        []byte
		incomplete bool
		want       string
	}{
		{grpcFrame([]byte("abc")), false, "[gRPC: 1 message, 3 payload bytes]"},
		{two, false, "[gRPC: 2 messages, 5 payload bytes]"},
		{two[:9], false, "[gRPC: 1+ messages, 3+ payload bytes]"},  // cut inside the second header
		{two[:14], false, "[gRPC: 2+ messages, 5+ payload bytes]"}, // cut inside the second payload
		{grpcFrame([]byte("abc")), true, "[gRPC: 1+ messages, 3+ payload bytes]"},
		{append([]byte{1, 0, 0, 0, 1}, 'x'), false, "[gRPC: 1 message, 1 payload bytes, 1 compressed]"},
	} {
		if got := GRPCSummary(tc.raw, tc.incomplete); got != tc.want {
			t.Errorf("GRPCSummary(%v, %v) = %q, want %q", tc.raw, tc.incomplete, got, tc.want)
		}
	}
}

func TestGRPCStatusLine(t *testing.T) {
	grpcHdr := http.Header{"Content-Type": {"application/grpc+proto"}}
	if got := GRPCStatusLine(grpcHdr, http.Header{"Grpc-Status": {"0"}}); got != "gRPC status: 0 OK" {
		t.Errorf("got %q", got)
	}
	// Trailers-only: an error without a body puts its status in the headers.
	only := http.Header{"Content-Type": {"application/grpc"}, "Grpc-Status": {"16"}, "Grpc-Message": {"bad%20token"}}
	if got := GRPCStatusLine(only, nil); got != "gRPC status: 16 UNAUTHENTICATED — bad token" {
		t.Errorf("got %q", got)
	}
	if got := GRPCStatusLine(http.Header{"Content-Type": {"application/json"}}, nil); got != "" {
		t.Errorf("non-gRPC got %q", got)
	}
}

// grpcFrame wraps payload in gRPC's 5-byte message framing.
func grpcFrame(payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}
