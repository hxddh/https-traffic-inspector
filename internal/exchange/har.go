package exchange

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
)

// HAR (HTTP Archive 1.2) conversion, for "httpmon query --format har": a
// session's exchanges, opened in a browser's developer tools or any HAR
// viewer.

// HARNameValue is a header, query parameter or cookie.
type HARNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARPostData is a request body.
type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"_encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// HARContent is a response body.
type HARContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// HARRequest is an entry's request.
type HARRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	QueryString []HARNameValue `json:"queryString"`
	Cookies     []HARNameValue `json:"cookies"`
	PostData    *HARPostData   `json:"postData,omitempty"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
}

// HARResponse is an entry's response.
type HARResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	Cookies     []HARNameValue `json:"cookies"`
	Content     HARContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
	// Non-standard fields, prefixed "_" as the spec allows. Chrome DevTools
	// reads _error for a request that failed.
	Error    string         `json:"_error,omitempty"`
	Trailers []HARNameValue `json:"_trailers,omitempty"`
}

// HARTimings are an entry's phases. Only the total is measured; it is
// reported as wait.
type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HARWSMessage is one WebSocket message in the form Chrome DevTools exports
// and imports.
type HARWSMessage struct {
	Type   string  `json:"type"` // "send" or "receive"
	Time   float64 `json:"time"` // seconds since the epoch
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}

// HAREntry is one exchange.
type HAREntry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         HARRequest     `json:"request"`
	Response        HARResponse    `json:"response"`
	Cache           struct{}       `json:"cache"`
	Timings         HARTimings     `json:"timings"`
	ResourceType    string         `json:"_resourceType,omitempty"`
	WSMessages      []HARWSMessage `json:"_webSocketMessages,omitempty"`
}

// HARTruncatedComment marks a body HAR holds only a prefix of.
const HARTruncatedComment = "httpmon: body truncated; only a prefix was captured"

// HARLog is a whole HAR file.
type HARLog struct {
	Log struct {
		Version string            `json:"version"`
		Creator map[string]string `json:"creator"`
		Entries []HAREntry        `json:"entries"`
	} `json:"log"`
}

// WriteHAR writes the exchanges as a HAR file.
func WriteHAR(w io.Writer, version string, list []*Exchange) error {
	h := NewHARStream(w, version)
	for _, e := range list {
		h.Add(e)
	}
	return h.Close()
}

// ToHAR converts one exchange. Bodies come from the raw bytes a session
// keeps, with any Content-Encoding removed; without them, from the rendering.
func ToHAR(e *Exchange) HAREntry {
	h := HAREntry{
		StartedDateTime: harTime(e.Time),
		Time:            e.DurationMs,
		Request: HARRequest{
			Method:      e.Method,
			URL:         e.URL,
			HTTPVersion: protoOr(e.Request.Proto),
			Headers:     harHeaders(e.Request.Headers),
			QueryString: harQuery(e.URL),
			Cookies:     []HARNameValue{},
			HeadersSize: -1,
		},
		Response: HARResponse{
			Headers:     []HARNameValue{},
			Cookies:     []HARNameValue{},
			Content:     HARContent{MimeType: "x-unknown"},
			HeadersSize: -1,
			BodySize:    -1,
		},
		Timings: HARTimings{Wait: e.DurationMs},
	}
	if b := e.Request.Body; b != nil {
		h.Request.BodySize = b.Size
		if text, enc, trunc, ok := harBody(e.Request.Headers, b); ok {
			mt := b.ContentType
			if mt == "" {
				mt = "application/octet-stream"
			}
			h.Request.PostData = &HARPostData{MimeType: mt, Text: text, Encoding: enc}
			if trunc {
				h.Request.PostData.Comment = HARTruncatedComment
			}
		}
	}
	if e.Error != nil {
		h.Response.Error = e.Error.Kind + ": " + e.Error.Message
		return h
	}
	r := e.Response
	if r == nil {
		return h
	}
	h.Response.Status = e.Status
	h.Response.StatusText = e.StatusText
	h.Response.HTTPVersion = protoOr(r.Proto)
	h.Response.Headers = harHeaders(r.Headers)
	if loc := r.Headers.HTTP().Get("Location"); loc != "" {
		h.Response.RedirectURL = loc
	}
	if len(r.Trailers) > 0 {
		h.Response.Trailers = harHeaders(r.Trailers)
	}
	if b := r.Body; b != nil {
		h.Response.BodySize = b.Size
		mt := b.ContentType
		if mt == "" {
			mt = "application/octet-stream"
		}
		h.Response.Content.MimeType = mt
		if text, enc, trunc, ok := harBody(r.Headers, b); ok {
			h.Response.Content.Text, h.Response.Content.Encoding = text, enc
			h.Response.Content.Size = int64(decodedLen(text, enc))
			if trunc {
				h.Response.Content.Comment = HARTruncatedComment
			}
		}
	} else {
		h.Response.BodySize = 0
	}
	if e.WebSocket != nil {
		h.ResourceType = "websocket"
		for _, m := range e.WebSocket.Messages {
			typ := "receive"
			if m.From == "client" {
				typ = "send"
			}
			data := m.Base64
			switch {
			case m.Type == "close":
				data = m.CloseReason
			case m.Text != nil:
				data = *m.Text
			}
			h.WSMessages = append(h.WSMessages, HARWSMessage{
				Type: typ, Time: harEpoch(m.Time), Opcode: wsOpcode(m.Type), Data: data,
			})
		}
	}
	return h
}

func protoOr(p string) string {
	if p == "" {
		return "HTTP/1.1"
	}
	return p
}

// harBody is a body's decoded bytes as HAR text: verbatim when valid UTF-8,
// base64 otherwise.
func harBody(headers Headers, b *body.Rendered) (text, encoding string, truncated, ok bool) {
	if b.Raw != nil {
		raw, err := b.Raw.Bytes()
		if err == nil {
			truncated = b.Raw.Truncated
			if ce := headers.HTTP().Get("Content-Encoding"); len(body.SplitEncodings(ce)) > 0 {
				if res, err := body.Decompress(ce, raw); err == nil {
					raw, truncated = res.Data, truncated || res.Truncated
				}
			}
			if utf8.Valid(raw) {
				return string(raw), "", truncated, true
			}
			return base64.StdEncoding.EncodeToString(raw), "base64", truncated, true
		}
	}
	// No raw bytes: the rendering is the best there is.
	switch {
	case b.Text != nil:
		return *b.Text, "", b.Truncated, true
	case b.JSON != nil:
		j, err := json.Marshal(b.JSON)
		if err == nil {
			return string(j), "", b.Truncated, true
		}
	}
	return "", "", false, false
}

func decodedLen(text, enc string) int {
	if enc == "base64" {
		return base64.StdEncoding.DecodedLen(len(text))
	}
	return len(text)
}

func harHeaders(h Headers) []HARNameValue {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]HARNameValue, 0, len(h))
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, HARNameValue{Name: k, Value: v})
		}
	}
	return out
}

func harQuery(raw string) []HARNameValue {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return []HARNameValue{}
	}
	vals, _ := url.ParseQuery(u.RawQuery)
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]HARNameValue, 0, len(vals))
	for _, k := range keys {
		for _, v := range vals[k] {
			out = append(out, HARNameValue{Name: k, Value: v})
		}
	}
	return out
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.000Z07:00", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func harTime(s string) string {
	if t, ok := parseTime(s); ok {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return s
}

func harEpoch(s string) float64 {
	if t, ok := parseTime(s); ok {
		return float64(t.UnixNano()) / 1e9
	}
	return 0
}

func wsOpcode(typ string) int {
	switch strings.ToLower(typ) {
	case "text":
		return 1
	case "binary":
		return 2
	case "close":
		return 8
	case "ping":
		return 9
	case "pong":
		return 10
	}
	return 0
}

// HARStream writes a HAR file one entry at a time, so a large session is
// never held in memory.
type HARStream struct {
	w   io.Writer
	n   int
	err error
}

// NewHARStream writes the HAR preamble.
func NewHARStream(w io.Writer, version string) *HARStream {
	creator, _ := json.Marshal(map[string]string{"name": "httpmon", "version": version})
	s := &HARStream{w: w}
	_, s.err = fmt.Fprintf(w, "{\n  \"log\": {\n    \"version\": \"1.2\",\n    \"creator\": %s,\n    \"entries\": [", creator)
	return s
}

// Add writes one exchange.
func (s *HARStream) Add(e *Exchange) {
	if s.err != nil {
		return
	}
	b, err := json.MarshalIndent(ToHAR(e), "      ", "  ")
	if err != nil {
		s.err = err
		return
	}
	sep := ",\n      "
	if s.n == 0 {
		sep = "\n      "
	}
	if _, s.err = io.WriteString(s.w, sep); s.err == nil {
		_, s.err = s.w.Write(b)
	}
	s.n++
}

// Close writes the closing brackets and reports any write error.
func (s *HARStream) Close() error {
	if s.err != nil {
		return s.err
	}
	end := "\n    ]\n  }\n}\n"
	if s.n == 0 {
		end = "]\n  }\n}\n"
	}
	_, s.err = io.WriteString(s.w, end)
	return s.err
}
