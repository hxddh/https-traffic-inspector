package body

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// DecodeProtobuf decodes a protobuf message without its schema, as
// protoc --decode_raw does: fields are named by number, and each value is
// shown as what its wire type can tell -- an integer, a nested message, a
// string, or bytes. A field that repeats becomes an array. It fails when b is
// not well-formed protobuf.
//
// Without the schema some readings are guesses: a fixed64 may be a double,
// and a length-delimited field that happens to parse as a message may really
// be bytes.
func DecodeProtobuf(b []byte) (Object, error) {
	return decodeMessage(b, 0)
}

const maxProtoDepth = 32

func decodeMessage(b []byte, depth int) (Object, error) {
	if depth > maxProtoDepth {
		return nil, errors.New("protobuf nested too deeply")
	}
	// Values are gathered per field, in the order fields first appear; a
	// field seen more than once becomes an array.
	var order []string
	values := map[string][]any{}
	add := func(field uint64, v any) {
		key := strconv.FormatUint(field, 10)
		if _, ok := values[key]; !ok {
			order = append(order, key)
		}
		values[key] = append(values[key], v)
	}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad field key")
		}
		b = b[n:]
		field, wire := key>>3, key&7
		if field == 0 {
			return nil, errors.New("field number 0")
		}
		switch wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			b = b[n:]
			add(field, protoInt(v))
		case 1:
			if len(b) < 8 {
				return nil, errors.New("short fixed64")
			}
			add(field, protoInt(binary.LittleEndian.Uint64(b)))
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("short fixed32")
			}
			add(field, protoInt(uint64(binary.LittleEndian.Uint32(b))))
			b = b[4:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) { //nolint:gosec // len(b)-n >= 0
				return nil, errors.New("bad length")
			}
			end := n + int(l) //nolint:gosec // l <= len(b)-n, checked above
			data := b[n:end]
			b = b[end:]
			add(field, decodeLengthDelimited(data, depth))
		default:
			return nil, errors.New("unsupported wire type " + strconv.FormatUint(wire, 10))
		}
	}
	obj := make(Object, 0, len(order))
	for _, k := range order {
		if vs := values[k]; len(vs) == 1 {
			obj = append(obj, Member{k, vs[0]})
		} else {
			obj = append(obj, Member{k, vs})
		}
	}
	return obj, nil
}

// protoInt keeps integers JSON can represent exactly as numbers, and larger
// ones as strings.
func protoInt(v uint64) any {
	if v <= 1<<53 {
		return v
	}
	return strconv.FormatUint(v, 10)
}

// decodeLengthDelimited reads a length-delimited field: readable text as a
// string, otherwise a nested message if it parses as one, otherwise bytes.
func decodeLengthDelimited(data []byte, depth int) any {
	if len(data) == 0 {
		return ""
	}
	if isReadableText(data) {
		return string(data)
	}
	if msg, err := decodeMessage(data, depth+1); err == nil && len(msg) > 0 {
		return msg
	}
	return Object{{Key: "bytes_base64", Value: base64.StdEncoding.EncodeToString(data)}}
}

func isReadableText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
	}
	return true
}
