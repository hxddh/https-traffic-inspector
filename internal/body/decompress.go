// Package body decodes and renders HTTP bodies: Content-Encoding, gRPC
// framing, protobuf and JSON.
package body

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// MaxDecompressed caps decoded output so a compression bomb cannot exhaust memory.
const MaxDecompressed = 10 << 20

// ErrUnsupportedEncoding is returned for a Content-Encoding httpmon cannot decode.
// Callers fall back to printing a "[<enc>, N bytes]" placeholder; returning the
// still-compressed bytes instead would render as garbage.
var ErrUnsupportedEncoding = errors.New("unsupported content-encoding")

// Result carries decoded bytes plus whether the output is incomplete,
// which happens when only a prefix of the compressed stream was captured or
// when MaxDecompressed was reached.
type Result struct {
	Data      []byte
	Truncated bool
}

// Decompress decodes data according to a Content-Encoding header value.
// Multiple encodings ("gzip, br") are decoded in reverse order, since the header
// lists them in the order they were applied. An empty or identity-only encoding
// returns data unchanged.
func Decompress(encoding string, data []byte) (Result, error) {
	return DecompressLimit(encoding, data, MaxDecompressed)
}

// DecompressLimit is Decompress with output capped at limit bytes, for
// callers that only show a prefix: decoding further would be wasted work.
func DecompressLimit(encoding string, data []byte, limit int) (Result, error) {
	res := Result{Data: data}
	layers := SplitEncodings(encoding)
	for i := len(layers) - 1; i >= 0; i-- {
		out, truncated, err := decodeLayer(layers[i], res.Data, limit)
		if err != nil {
			return Result{}, err
		}
		res.Data = out
		if truncated {
			// Remaining layers cannot be decoded from a partial stream.
			res.Truncated = true
			break
		}
	}
	return res, nil
}

// SplitEncodings splits a Content-Encoding value into lowercase layers,
// dropping empty entries and "identity".
func SplitEncodings(encoding string) []string {
	var out []string
	for _, f := range strings.Split(encoding, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" || f == "identity" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func decodeLayer(enc string, data []byte, limit int) ([]byte, bool, error) {
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false, err
		}
		defer zr.Close()
		return readTolerant(zr, limit)

	case "deflate":
		// RFC 7230 specifies zlib-wrapped deflate, but some servers send a raw
		// deflate stream. Try zlib first and fall back to raw.
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			defer zr.Close()
			if out, truncated, err := readTolerant(zr, limit); err == nil {
				return out, truncated, nil
			}
		}
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		return readTolerant(fr, limit)

	case "br":
		return readTolerant(brotli.NewReader(bytes.NewReader(data)), limit)

	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false, err
		}
		defer zr.Close()
		return readTolerant(zr.IOReadCloser(), limit)

	default:
		return nil, false, fmt.Errorf("%w: %s", ErrUnsupportedEncoding, enc)
	}
}

// readTolerant reads up to limit bytes from r. A stream that ends
// early — the normal case when only a prefix of the body was captured — yields
// the bytes decoded so far with truncated=true instead of an error, so a large
// response still shows its readable beginning.
func readTolerant(r io.Reader, limit int) ([]byte, bool, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, int64(limit)))
	if err != nil {
		if buf.Len() > 0 {
			return buf.Bytes(), true, nil
		}
		return nil, false, err
	}
	return buf.Bytes(), n == int64(limit), nil
}
