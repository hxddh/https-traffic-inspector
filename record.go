package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ---- record format v2 ----
//
// One JSON object per line, each a complete exchange. Unlike v1, which stored
// the human-readable view of each body (and so a placeholder for anything
// binary), v2 stores what crossed the wire:
//
//   - headers as an ordered list of [name, value] pairs, so repeated headers
//     such as Set-Cookie survive;
//   - bodies as their raw bytes -- UTF-8 text verbatim, anything else base64 --
//     with the decoded text alongside when the body was compressed;
//   - a session id and sequence number, unique across appended runs;
//   - failed exchanges, with the error, and WebSocket messages.

const recordVersion = 2

type recordV2 struct {
	V       int    `json:"v"`
	Session string `json:"session"`
	Seq     int    `json:"seq"`
	Time    string `json:"time"`
	Kind    string `json:"kind"` // "http" or "websocket"

	Method     string     `json:"method"`
	URL        string     `json:"url"`
	Proto      string     `json:"proto,omitempty"`
	ReqHeaders headerList `json:"req_headers"`
	ReqBody    *recBody   `json:"req_body,omitempty"`

	Status       int        `json:"status,omitempty"`
	StatusText   string     `json:"status_text,omitempty"`
	RespProto    string     `json:"resp_proto,omitempty"`
	RespHeaders  headerList `json:"resp_headers,omitempty"`
	RespBody     *recBody   `json:"resp_body,omitempty"`
	RespTrailers headerList `json:"resp_trailers,omitempty"`

	DurationMs float64 `json:"duration_ms"`
	// Error is set, and the response fields are empty, when no response came.
	Error string `json:"error,omitempty"`

	WSMessages []recWSMessage `json:"ws_messages,omitempty"`
	WSDropped  int            `json:"ws_dropped,omitempty"`

	// Redacted marks a recording made with --redact: credentials in headers
	// and the URL are masked, so requests that carried them cannot be replayed.
	Redacted bool `json:"redacted,omitempty"`
}

// headerList is an ordered list of [name, value] pairs.
type headerList [][2]string

// recBody is a body as it crossed the wire.
type recBody struct {
	Encoding  string `json:"encoding"` // "utf8" or "base64"
	Data      string `json:"data"`
	Size      int64  `json:"size"` // bytes on the wire; more than Data holds when truncated
	Truncated bool   `json:"truncated,omitempty"`
	// Decoded is the text with its Content-Encoding removed, when the body
	// was compressed and decodes to text.
	Decoded string `json:"decoded,omitempty"`
}

type recWSMessage struct {
	From        string `json:"from"` // "client" or "server"
	Time        string `json:"time"`
	Type        string `json:"type"`
	Size        int64  `json:"size"`
	Encoding    string `json:"encoding,omitempty"`
	Data        string `json:"data,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	CloseCode   int    `json:"close_code,omitempty"`
	CloseReason string `json:"close_reason,omitempty"`
}

// toHeaderList orders h by name, keeping each name's values in order.
func toHeaderList(h http.Header) headerList {
	if len(h) == 0 {
		return nil
	}
	out := make(headerList, 0, len(h))
	for _, k := range sortedKeys(h) {
		for _, v := range h[k] {
			out = append(out, [2]string{k, v})
		}
	}
	return out
}

func (l headerList) header() http.Header {
	h := make(http.Header, len(l))
	for _, kv := range l {
		h.Add(kv[0], kv[1])
	}
	return h
}

// encodeBytes stores b as UTF-8 text when it is, and base64 otherwise.
func encodeBytes(b []byte) (encoding, data string) {
	if utf8.Valid(b) {
		return "utf8", string(b)
	}
	return "base64", base64.StdEncoding.EncodeToString(b)
}

func decodeBytes(encoding, data string) ([]byte, error) {
	if encoding == "base64" {
		return base64.StdEncoding.DecodeString(data)
	}
	return []byte(data), nil
}

func newRecBody(h http.Header, v bodyView) *recBody {
	if v.Size == 0 && len(v.Raw) == 0 {
		return nil
	}
	b := &recBody{Size: v.Size, Truncated: v.RawTruncated}
	b.Encoding, b.Data = encodeBytes(v.Raw)
	if len(splitEncodings(h.Get("Content-Encoding"))) > 0 {
		if dec, err := decompressBody(h.Get("Content-Encoding"), v.Raw); err == nil &&
			utf8.Valid(dec.Data) && isPrintableContentType(h.Get("Content-Type")) {
			b.Decoded = string(dec.Data)
		}
	}
	return b
}

// recordFile is the open file used by the proxy when --record is active.
var (
	recordFile    *os.File
	recordEncoder *json.Encoder
	// recordMu serialises writes: exchanges complete concurrently, and a
	// json.Encoder is not safe for concurrent use, so unguarded writes could
	// interleave two records on one line.
	recordMu sync.Mutex

	// recordSession identifies this run's records in a file appended to by
	// several runs.
	recordSession = newSessionID()
)

func newSessionID() string {
	var b [4]byte
	rand.Read(b[:]) //nolint:errcheck // never fails
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// openRecordFile opens (or creates) the NDJSON recording file.
func openRecordFile(path string) error {
	// 0600: recordings carry whole request headers, including Authorization
	// values and cookies, so they must not be world-readable.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	recordFile = f
	recordEncoder = json.NewEncoder(f)
	return nil
}

func millis(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000
}

// buildRecord turns a completed exchange into a v2 record.
func buildRecord(id int, r capturedRequest, rs capturedResponse) recordV2 {
	e := recordV2{
		V:          recordVersion,
		Session:    recordSession,
		Seq:        id,
		Time:       r.facts.startTime.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		Kind:       "http",
		Method:     r.facts.method,
		URL:        captureURL(r.facts.rawURL),
		Proto:      r.facts.proto,
		ReqHeaders: toHeaderList(captureHeaders(r.facts.headers)),
		ReqBody:    newRecBody(r.facts.headers, r.body),
		DurationMs: millis(rs.facts.totalDuration()),
		Redacted:   redactCaptures,
	}
	if rs.err != "" {
		e.Error = rs.err
		return e
	}
	e.Status = rs.facts.status
	e.StatusText = rs.facts.statusText
	e.RespProto = rs.facts.proto
	e.RespHeaders = toHeaderList(captureHeaders(rs.facts.headers))
	e.RespBody = newRecBody(rs.facts.headers, rs.body)
	e.RespTrailers = toHeaderList(captureHeaders(rs.facts.trailers))
	if rs.facts.upgraded {
		e.Kind = "websocket"
		for _, m := range rs.ws {
			rm := recWSMessage{
				From: m.sender(), Time: m.at.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
				Type: m.typeName(), Size: m.size, Truncated: m.truncated,
				CloseCode: m.closeCode, CloseReason: m.closeReason,
			}
			if m.opcode != wsClose && len(m.data) > 0 {
				rm.Encoding, rm.Data = encodeBytes(m.data)
			}
			e.WSMessages = append(e.WSMessages, rm)
		}
	}
	return e
}

// writeRecord appends one completed exchange to the recording.
func writeRecord(id int, r capturedRequest, rs capturedResponse) {
	e := buildRecord(id, r, rs)
	recordMu.Lock()
	defer recordMu.Unlock()
	if recordEncoder != nil {
		recordEncoder.Encode(e) //nolint:errcheck
	}
}

// isSensitiveHeaderList reports whether any header in l carries credentials.
func (l headerList) hasSensitive() bool {
	for _, kv := range l {
		if isSensitiveHeader(kv[0]) {
			return true
		}
	}
	return false
}

// redactedURL reports whether u had a credential masked by --redact.
func redactedURL(u string) bool {
	return strings.Contains(u, "…(") || strings.Contains(u, ":…@")
}
