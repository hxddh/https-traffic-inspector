package body

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Object is a JSON object that keeps its members in their original order,
// which encoding/json's map decoding would lose.
type Object []Member

// Member is one name/value pair of an Object.
type Member struct {
	Key   string
	Value any
}

// MarshalJSON writes the members in order.
func (o Object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(m.Key)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		v, err := marshalNoEscape(m.Value)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Get returns the value of the first member named key.
func (o Object) Get(key string) (any, bool) {
	for _, m := range o {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// ParseJSON decodes data, keeping object member order. Numbers are kept as
// json.Number so they are written back exactly as they came.
func ParseJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := Object{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("object key is %T", kt)
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj = append(obj, Member{key, v})
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return t, nil
	}
}

// truncLevel is one step of progressively tighter limits.
type truncLevel struct{ str, arr, obj, depth int }

var truncLevels = []truncLevel{
	{200, 10, 50, 8},
	{80, 5, 20, 6},
	{40, 3, 10, 4},
	{20, 2, 6, 3},
	{12, 1, 3, 2},
}

// TruncateJSON shrinks v until its encoding fits in about budget bytes, while
// keeping it valid JSON with the same shape: long strings are cut, long arrays
// keep their first items, large objects their first members, and deep nesting
// is summarised. Each cut says what it left out ("…(+37 more items)"). It
// reports whether anything was cut.
func TruncateJSON(v any, budget int) (any, bool) {
	if b, err := marshalNoEscape(v); err == nil && len(b) <= budget {
		return v, false
	}
	var out any
	for _, l := range truncLevels {
		out = shrink(v, l, 0)
		if b, err := marshalNoEscape(out); err == nil && len(b) <= budget {
			return out, true
		}
	}
	return out, true
}

func shrink(v any, l truncLevel, depth int) any {
	switch t := v.(type) {
	case string:
		if n := utf8.RuneCountInString(t); n > l.str {
			r := []rune(t)
			return string(r[:l.str]) + fmt.Sprintf("…(+%d chars)", n-l.str)
		}
		return t
	case []any:
		if depth >= l.depth {
			return fmt.Sprintf("…(array, %d items)", len(t))
		}
		n := len(t)
		keep := n
		if keep > l.arr {
			keep = l.arr
		}
		out := make([]any, 0, keep+1)
		for _, e := range t[:keep] {
			out = append(out, shrink(e, l, depth+1))
		}
		if n > keep {
			out = append(out, fmt.Sprintf("…(+%d more items)", n-keep))
		}
		return out
	case Object:
		if depth >= l.depth {
			return fmt.Sprintf("…(object, %d keys)", len(t))
		}
		keep := len(t)
		if keep > l.obj {
			keep = l.obj
		}
		out := make(Object, 0, keep+1)
		for _, m := range t[:keep] {
			out = append(out, Member{m.Key, shrink(m.Value, l, depth+1)})
		}
		if len(t) > keep {
			out = append(out, Member{"…", fmt.Sprintf("+%d more keys", len(t)-keep)})
		}
		return out
	}
	return v
}

// ErrorHint finds a short error description in a JSON error body, from the
// fields APIs commonly use: error.code, error.type, error.message, code,
// message, detail, title, or a string-valued error. It returns "" when there
// is none.
func ErrorHint(v any) string {
	get := func(v any, key string) any {
		switch o := v.(type) {
		case Object:
			x, _ := o.Get(key)
			return x
		case map[string]any:
			return o[key]
		}
		return nil
	}
	str := func(x any) string {
		switch s := x.(type) {
		case string:
			return s
		case json.Number:
			return s.String()
		case float64:
			return fmt.Sprint(s)
		}
		return ""
	}
	if e := get(v, "error"); e != nil {
		if s := str(e); s != "" {
			return clip(s)
		}
		for _, k := range []string{"code", "type", "status", "message"} {
			if s := str(get(e, k)); s != "" {
				return clip(s)
			}
		}
	}
	for _, k := range []string{"code", "error_code", "message", "detail", "title", "error_description"} {
		if s := str(get(v, k)); s != "" {
			return clip(s)
		}
	}
	if errs, ok := get(v, "errors").([]any); ok && len(errs) > 0 {
		if s := str(errs[0]); s != "" {
			return clip(s)
		}
		for _, k := range []string{"code", "message"} {
			if s := str(get(errs[0], k)); s != "" {
				return clip(s)
			}
		}
	}
	return ""
}

func clip(s string) string {
	const max = 60
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}
