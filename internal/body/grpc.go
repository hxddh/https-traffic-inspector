package body

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// IsGRPC reports whether ct is a gRPC content type
// (application/grpc, optionally with a +proto, +json… suffix).
func IsGRPC(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") ||
		strings.HasPrefix(ct, "application/grpc;")
}

// GRPCSummary describes a gRPC body. Messages are length-prefixed binary
// (usually protobuf), so printing them would show noise; the framing, though,
// says how many messages went by and how large they were.
//
// Each message is a 1-byte compressed flag and a 4-byte big-endian length,
// followed by that many bytes.
func GRPCSummary(raw []byte, incomplete bool) string {
	var msgs, compressed int
	var payload int64
	rest := raw
	partial := false
	for len(rest) > 0 {
		if len(rest) < 5 {
			partial = true
			break
		}
		n := int64(binary.BigEndian.Uint32(rest[1:5]))
		msgs++
		payload += n
		if rest[0]&1 == 1 {
			compressed++
		}
		if int64(len(rest)-5) < n {
			partial = true
			break
		}
		rest = rest[5+n:]
	}

	more := ""
	if incomplete || partial {
		more = "+"
	}
	noun := "messages"
	if msgs == 1 && more == "" {
		noun = "message"
	}
	s := fmt.Sprintf("[gRPC: %d%s %s, %d%s payload bytes", msgs, more, noun, payload, more)
	if compressed > 0 {
		s += fmt.Sprintf(", %d compressed", compressed)
	}
	return s + "]"
}

// grpcCodeNames are the canonical gRPC status codes.
var grpcCodeNames = []string{
	"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
	"NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED",
	"FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED",
	"INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED",
}

// GRPCStatusLine summarises a gRPC call's outcome, which lives in the
// trailers -- or in the headers of a trailers-only response, the form an error
// without a body takes. It returns "" for anything that is not gRPC.
func GRPCStatusLine(headers, trailers http.Header) string {
	if !IsGRPC(headers.Get("Content-Type")) {
		return ""
	}
	src := trailers
	if src.Get("Grpc-Status") == "" {
		src = headers
	}
	code := src.Get("Grpc-Status")
	if code == "" {
		return "gRPC status: missing (the call ended without grpc-status)"
	}
	name := "?"
	if n, err := strconv.Atoi(code); err == nil && n >= 0 && n < len(grpcCodeNames) {
		name = grpcCodeNames[n]
	}
	line := fmt.Sprintf("gRPC status: %s %s", code, name)
	if msg := src.Get("Grpc-Message"); msg != "" {
		// grpc-message is percent-encoded on the wire.
		if dec, err := url.PathUnescape(msg); err == nil {
			msg = dec
		}
		line += " — " + msg
	}
	return line
}

// GRPCStatus returns a call's status code, from the trailers or, for a
// trailers-only response, the headers.
func GRPCStatus(headers, trailers http.Header) string {
	if s := trailers.Get("Grpc-Status"); s != "" {
		return s
	}
	return headers.Get("Grpc-Status")
}

// GRPCCodeName names a gRPC status code.
func GRPCCodeName(code int) string {
	if code >= 0 && code < len(grpcCodeNames) {
		return grpcCodeNames[code]
	}
	return ""
}
