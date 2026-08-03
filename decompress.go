package main

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

// maxDecompressed caps decoded output so a compression bomb cannot exhaust memory.
const maxDecompressed = 10 << 20

// errUnsupportedEncoding is returned for a Content-Encoding httpmon cannot decode.
// Callers fall back to printing a "[<enc>, N bytes]" placeholder; returning the
// still-compressed bytes instead would render as garbage.
var errUnsupportedEncoding = errors.New("unsupported content-encoding")

// decodeResult carries decoded bytes plus whether the output is incomplete,
// which happens when only a prefix of the compressed stream was captured or
// when maxDecompressed was reached.
type decodeResult struct {
	Data      []byte
	Truncated bool
}

// decompressBody decodes data according to a Content-Encoding header value.
// Multiple encodings ("gzip, br") are decoded in reverse order, since the header
// lists them in the order they were applied. An empty or identity-only encoding
// returns data unchanged.
func decompressBody(encoding string, data []byte) (decodeResult, error) {
	res := decodeResult{Data: data}
	layers := splitEncodings(encoding)
	for i := len(layers) - 1; i >= 0; i-- {
		out, truncated, err := decodeLayer(layers[i], res.Data)
		if err != nil {
			return decodeResult{}, err
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

// splitEncodings splits a Content-Encoding value into lowercase layers,
// dropping empty entries and "identity".
func splitEncodings(encoding string) []string {
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

func decodeLayer(enc string, data []byte) ([]byte, bool, error) {
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false, err
		}
		defer zr.Close()
		return readTolerant(zr)

	case "deflate":
		// RFC 7230 specifies zlib-wrapped deflate, but some servers send a raw
		// deflate stream. Try zlib first and fall back to raw.
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			defer zr.Close()
			if out, truncated, err := readTolerant(zr); err == nil {
				return out, truncated, nil
			}
		}
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		return readTolerant(fr)

	case "br":
		return readTolerant(brotli.NewReader(bytes.NewReader(data)))

	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false, err
		}
		defer zr.Close()
		return readTolerant(zr.IOReadCloser())

	default:
		return nil, false, fmt.Errorf("%w: %s", errUnsupportedEncoding, enc)
	}
}

// readTolerant reads up to maxDecompressed bytes from r. A stream that ends
// early — the normal case when only a prefix of the body was captured — yields
// the bytes decoded so far with truncated=true instead of an error, so a large
// response still shows its readable beginning.
func readTolerant(r io.Reader) ([]byte, bool, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, maxDecompressed))
	if err != nil {
		if buf.Len() > 0 {
			return buf.Bytes(), true, nil
		}
		return nil, false, err
	}
	return buf.Bytes(), n == maxDecompressed, nil
}
