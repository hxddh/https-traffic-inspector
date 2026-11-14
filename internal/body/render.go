package body

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Rendered is a body as httpmon reports it in JSON: decoded from its
// Content-Encoding and given in the most useful form -- a JSON value, text,
// decoded gRPC messages, or just the fact that it is binary. Raw, when
// present, holds the bytes exactly as they crossed the wire.
type Rendered struct {
	Size            int64  `json:"size"` // bytes on the wire
	ContentType     string `json:"content_type,omitempty"`
	ContentEncoding string `json:"content_encoding,omitempty"`

	JSON   any           `json:"json,omitempty"`
	Text   *string       `json:"text,omitempty"`
	GRPC   []GRPCMessage `json:"grpc,omitempty"`
	Binary bool          `json:"binary,omitempty"`

	// Truncated means the rendering is shortened -- by the output budget, or
	// because only part of the body was captured.
	Truncated bool `json:"truncated,omitempty"`

	Raw *Raw `json:"raw,omitempty"`
}

// Raw is a body's wire bytes: UTF-8 text verbatim, anything else base64.
type Raw struct {
	Encoding  string `json:"encoding"` // "utf8" or "base64"
	Data      string `json:"data"`
	Truncated bool   `json:"truncated,omitempty"` // only a prefix was captured
}

// NewRaw encodes wire bytes for storage.
func NewRaw(b []byte, truncated bool) *Raw {
	if utf8.Valid(b) {
		return &Raw{Encoding: "utf8", Data: string(b), Truncated: truncated}
	}
	return &Raw{Encoding: "base64", Data: base64.StdEncoding.EncodeToString(b), Truncated: truncated}
}

// Bytes decodes the stored bytes.
func (r *Raw) Bytes() ([]byte, error) {
	if r.Encoding == "base64" {
		return base64.StdEncoding.DecodeString(r.Data)
	}
	return []byte(r.Data), nil
}

// GRPCMessage is one message of a gRPC body, decoded without a schema.
type GRPCMessage struct {
	Size       int    `json:"size"`
	Compressed bool   `json:"compressed,omitempty"`
	Fields     Object `json:"fields,omitempty"`
	// Undecoded is set when the message could not be read as protobuf.
	Undecoded bool `json:"undecoded,omitempty"`
}

// DecodeGRPC splits a gRPC body into its length-prefixed messages and decodes
// each one. It reports whether the body ended partway through a message.
func DecodeGRPC(raw []byte) ([]GRPCMessage, bool) {
	var out []GRPCMessage
	for len(raw) > 0 {
		if len(raw) < 5 {
			return out, true
		}
		n := int(binary.BigEndian.Uint32(raw[1:5]))
		m := GRPCMessage{Size: n, Compressed: raw[0]&1 == 1}
		if len(raw)-5 < n {
			m.Undecoded = true
			out = append(out, m)
			return out, true
		}
		payload := raw[5 : 5+n]
		raw = raw[5+n:]
		if m.Compressed {
			m.Undecoded = true
		} else if f, err := DecodeProtobuf(payload); err == nil {
			m.Fields = f
		} else {
			m.Undecoded = true
		}
		out = append(out, m)
	}
	return out, false
}

// LooksLikeJSONType reports whether a Content-Type names JSON.
func LooksLikeJSONType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "json")
}

// PrintableType reports whether a Content-Type suggests human-readable text.
func PrintableType(ct string) bool {
	ct = strings.ToLower(ct)
	if ct == "" {
		return true
	}
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "html") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "form")
}

// Render decodes raw according to h and renders it within about budget
// bytes. rawTruncated reports that raw is only a prefix of the body; size is
// the number of bytes that crossed the wire. It returns nil for an empty body.
//
// It also returns a short error description found in a JSON body (see
// ErrorHint), taken from the whole body before it is cut to the budget, so an
// error code deep in a large body is still found.
func Render(h http.Header, raw []byte, rawTruncated bool, size int64, budget int) (*Rendered, string) {
	if size == 0 && len(raw) == 0 {
		return nil, ""
	}
	ct := h.Get("Content-Type")
	enc := h.Get("Content-Encoding")
	r := &Rendered{Size: size, ContentType: ct, ContentEncoding: enc}

	data, truncated := raw, rawTruncated
	if len(SplitEncodings(enc)) > 0 {
		res, err := Decompress(enc, raw)
		if err != nil {
			r.Binary = true
			return r, ""
		}
		data, truncated = res.Data, truncated || res.Truncated
	}

	switch {
	case IsGRPC(ct):
		msgs, partial := DecodeGRPC(data)
		r.GRPC = msgs
		r.Truncated = truncated || partial
		// Keep the rendering within budget: drop messages past it, then
		// shorten the fields of those kept, so one large message cannot
		// flood the output either.
		for len(r.GRPC) > 1 && approxLen(r.GRPC) > budget {
			r.GRPC = r.GRPC[:len(r.GRPC)/2]
			r.Truncated = true
		}
		if len(r.GRPC) > 0 {
			per := budget / len(r.GRPC)
			for i := range r.GRPC {
				if r.GRPC[i].Fields == nil {
					continue
				}
				v, cut := TruncateJSON(r.GRPC[i].Fields, per)
				if obj, ok := v.(Object); ok && cut {
					r.GRPC[i].Fields = obj
					r.Truncated = true
				}
			}
		}
		return r, ""

	case !truncated && (LooksLikeJSONType(ct) || (ct == "" && looksLikeJSONData(data))):
		if v, err := ParseJSON(data); err == nil {
			hint := ErrorHint(v)
			v, cut := TruncateJSON(v, budget)
			r.JSON, r.Truncated = v, cut
			return r, hint
		}
	}

	if PrintableType(ct) && (ct != "" || utf8.Valid(trimPartialRune(data, truncated))) {
		s := string(trimPartialRune(data, truncated))
		if len(s) > budget {
			cut := budget
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
			s, truncated = s[:cut], true
		}
		r.Text, r.Truncated = &s, truncated
		return r, ""
	}
	r.Binary = true
	r.Truncated = truncated
	return r, ""
}

func looksLikeJSONData(b []byte) bool {
	s := strings.TrimSpace(string(b))
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

// trimPartialRune drops a multi-byte character cut in half at the end of a
// captured prefix.
func trimPartialRune(b []byte, truncated bool) []byte {
	if !truncated {
		return b
	}
	for i := 0; i < 3 && len(b) > 0 && !utf8.Valid(b); i++ {
		b = b[:len(b)-1]
	}
	return b
}

func approxLen(msgs []GRPCMessage) int {
	b, err := marshalNoEscape(msgs)
	if err != nil {
		return 0
	}
	return len(b)
}
