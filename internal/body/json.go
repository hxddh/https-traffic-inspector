package body

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
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

// UnmarshalJSON reads an object back in member order, so records holding
// decoded fields can be read by query and replay.
func (o *Object) UnmarshalJSON(data []byte) error {
	v, err := ParseJSON(data)
	if err != nil {
		return err
	}
	obj, ok := v.(Object)
	if !ok {
		return fmt.Errorf("expected a JSON object, got %T", v)
	}
	*o = obj
	return nil
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

// SoftErrorHint inspects a parsed JSON body for protocol-level errors commonly
// returned inside an HTTP 200 OK response: GraphQL "errors" arrays and
// JSON-RPC 2.0 "error" objects. It returns ("", "") for normal payloads.
func SoftErrorHint(v any) (kind, hint string) {
	obj, ok := v.(Object)
	if !ok {
		return "", ""
	}
	if _, isRPC := obj.Get("jsonrpc"); isRPC {
		if e, hasErr := obj.Get("error"); hasErr && e != nil {
			h := ErrorHint(obj)
			if h == "" {
				h = "jsonrpc_error"
			}
			return "jsonrpc", h
		}
	}
	errsVal, hasErrs := obj.Get("errors")
	errs, ok := errsVal.([]any)
	if !hasErrs || !ok || len(errs) == 0 {
		return "", ""
	}
	_, hasData := obj.Get("data")
	e0, e0Obj := errs[0].(Object)
	isGQL := hasData
	if e0Obj && !isGQL {
		_, hasMsg := e0.Get("message")
		_, hasLoc := e0.Get("locations")
		_, hasPath := e0.Get("path")
		_, hasExt := e0.Get("extensions")
		isGQL = hasMsg && (hasLoc || hasPath || hasExt)
	}
	if !isGQL {
		return "", ""
	}
	if e0Obj {
		if ext, ok := objObj(e0, "extensions"); ok {
			if code := objStr(ext, "code"); code != "" {
				return "graphql", clip(code)
			}
		}
		if code := objStr(e0, "code"); code != "" {
			return "graphql", clip(code)
		}
		if msg := objStr(e0, "message"); msg != "" {
			return "graphql", clip(msg)
		}
	}
	return "graphql", "graphql_error"
}

var gqlOpRE = regexp.MustCompile(`^(query|mutation|subscription)\b(?:\s+([A-Za-z_][A-Za-z0-9_]*))?`)

// GraphQLOperation extracts the operation kind and name (e.g. "mutation CreateOrder")
// from a GraphQL JSON request body, or "" when v is not one.
func GraphQLOperation(v any) string {
	obj, ok := v.(Object)
	if !ok {
		return ""
	}
	q := objStr(obj, "query")
	if q == "" {
		return ""
	}
	opName := objStr(obj, "operationName")
	// Strip leading whitespace and # comment lines.
	lines := strings.Split(q, "\n")
	var trimmed strings.Builder
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		trimmed.WriteString(t)
		trimmed.WriteByte(' ')
		if trimmed.Len() > 128 {
			break
		}
	}
	head := strings.TrimSpace(trimmed.String())
	if m := gqlOpRE.FindStringSubmatch(head); m != nil {
		kind := m[1]
		name := opName
		if name == "" {
			name = m[2]
		}
		if name != "" {
			return kind + " " + name
		}
		return kind
	}
	if strings.HasPrefix(head, "{") {
		if opName != "" {
			return "query " + opName
		}
		return "query"
	}
	return ""
}

var tolerantErrRE = regexp.MustCompile(`"(?:code|error_code|type|error|message|detail|title)"\s*:\s*"([^"\\]{1,80})"`)

// TolerantErrorHint extracts an error code or message from the captured prefix
// of a truncated JSON body that cannot be parsed as a whole.
func TolerantErrorHint(data []byte) string {
	if len(data) > 8192 {
		data = data[:8192]
	}
	if m := tolerantErrRE.FindSubmatch(data); m != nil {
		return clip(string(m[1]))
	}
	return ""
}
