package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"strings"
)

// decompressBody decompresses data according to the Content-Encoding value.
// Returns the original data unchanged for unrecognised or empty encodings.
// The decompressed output is capped at 10 MiB to prevent memory exhaustion.
func decompressBody(encoding string, data []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(io.LimitReader(r, 10<<20))
	case "deflate":
		rc := flate.NewReader(bytes.NewReader(data))
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 10<<20))
	default:
		return data, nil
	}
}
