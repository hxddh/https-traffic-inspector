package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
)

// ---- exchange records ----
//
// One shape serves both --format json and --record: an exchange.Exchange,
// request and response together. The JSON output carries bodies rendered for
// reading -- a JSON value, text, decoded gRPC -- cut to --max-body; a record
// carries the same plus each body's raw bytes, which replay needs.

// recordSession identifies this run's records in a file appended to by
// several runs.
var recordSession = newSessionID()

func newSessionID() string {
	var b [4]byte
	rand.Read(b[:]) //nolint:errcheck // never fails
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func millis(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000
}

// buildExchange turns a completed exchange into its record. forRecord selects
// the --record form: masked only under --redact, and with raw bytes; otherwise
// it is the displayed form, masked unless --show-secrets.
func buildExchange(id int, r capturedRequest, rs capturedResponse, forRecord bool) *exchange.Exchange {
	headers, url := displayHeaders, displayURL
	if forRecord {
		headers, url = captureHeaders, captureURL
	}
	e := &exchange.Exchange{
		V:          exchange.Version,
		Session:    recordSession,
		ID:         id,
		Time:       exchange.FormatTime(r.facts.startTime),
		Kind:       "http",
		Method:     r.facts.method,
		URL:        url(r.facts.rawURL),
		DurationMs: millis(rs.facts.totalDuration()),
		Request: exchange.Message{
			Proto:   r.facts.proto,
			Headers: exchange.FromHTTP(headers(r.facts.headers)),
		},
		Redacted: forRecord && redactCaptures,
		Rule:     ruleLabel(id),
	}
	e.Request.Body, _ = renderBody(r.facts.headers, r.body, forRecord)
	if rs.err != nil {
		e.Error = rs.err
		return e
	}

	f := rs.facts
	e.Status = f.status
	e.StatusText = statusText(f.statusText)
	resp := &exchange.Message{
		Proto:   f.proto,
		Headers: exchange.FromHTTP(headers(f.headers)),
	}
	if len(f.trailers) > 0 {
		resp.Trailers = exchange.FromHTTP(headers(f.trailers))
	}
	var hint string
	resp.Body, hint = renderBody(f.headers, rs.body, forRecord)
	if f.status >= 400 {
		e.Hint = hint
	}
	e.Response = resp

	if body.IsGRPC(f.headers.Get("Content-Type")) {
		if code := body.GRPCStatus(f.headers, f.trailers); code != "" {
			n, _ := strconv.Atoi(code)
			msg := f.trailers.Get("Grpc-Message")
			if msg == "" {
				msg = f.headers.Get("Grpc-Message")
			}
			e.GRPC = &exchange.GRPCStatus{Code: n, Name: body.GRPCCodeName(n), Message: msg}
		}
	}

	if f.upgraded {
		e.Kind = "websocket"
		e.WebSocket = &exchange.WebSocket{Messages: []exchange.WSMessage{}, Dropped: rs.wsDropped}
		for _, m := range rs.ws {
			e.WebSocket.Messages = append(e.WebSocket.Messages, wsRecord(m, forRecord))
		}
	}
	return e
}

// statusText strips the code from "404 Not Found".
func statusText(s string) string {
	if len(s) > 4 && s[3] == ' ' {
		return s[4:]
	}
	return s
}

// renderBody renders a captured body; a record also keeps the raw bytes.
func renderBody(h http.Header, v bodyView, forRecord bool) (*body.Rendered, string) {
	r, hint := body.Render(h, v.Raw, v.RawTruncated, v.Size, displayMaxBody)
	if r != nil && forRecord {
		r.Raw = body.NewRaw(v.Raw, v.RawTruncated)
	}
	return r, hint
}

func wsRecord(m wsMessage, forRecord bool) exchange.WSMessage {
	rm := exchange.WSMessage{
		From: m.sender(), Time: exchange.FormatTime(m.at), Type: m.typeName(), Size: m.size,
		Compressed: m.compressed, Truncated: m.truncated,
		CloseCode: m.closeCode, CloseReason: m.closeReason,
	}
	if m.opcode == wsClose || len(m.data) == 0 {
		return rm
	}
	data := m.data
	if !forRecord && len(data) > displayMaxBody {
		data, rm.Truncated = data[:displayMaxBody], true
	}
	if utf8.Valid(data) {
		s := string(data)
		rm.Text = &s
	} else {
		rm.Base64 = base64.StdEncoding.EncodeToString(data)
	}
	return rm
}

// ---- --record ----

var (
	recordFile    *os.File
	recordEncoder *json.Encoder
	// recordMu serialises writes: exchanges complete concurrently, and a
	// json.Encoder is not safe for concurrent use, so unguarded writes could
	// interleave two records on one line.
	recordMu sync.Mutex
)

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
	recordEncoder.SetEscapeHTML(false)
	return nil
}

// writeRecord appends one completed exchange to the recording.
func writeRecord(e *exchange.Exchange) {
	recordMu.Lock()
	defer recordMu.Unlock()
	if recordEncoder != nil {
		recordEncoder.Encode(e) //nolint:errcheck
	}
}

// ---- run statistics ----

// stats feeds the end-of-run digest and --fail-on.
type stats struct {
	mu     sync.Mutex
	digest exchange.Digest
	failOn *exchange.FailOn
}

var runStats = &stats{}

func (s *stats) add(e *exchange.Exchange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.digest.Add(e)
	if s.failOn.Match(e) {
		s.digest.Matched = append(s.digest.Matched, e.ID)
	}
}

// final returns the digest for the end of the run, given the exchanges
// still unfinished.
func (s *stats) final(pending []exchange.Pending) *exchange.Digest {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.digest
	d.Matched = append([]int(nil), d.Matched...)
	d.Incomplete = len(pending)
	if s.failOn.MatchIncomplete() {
		for _, p := range pending {
			d.Matched = append(d.Matched, p.ID)
		}
	}
	if d.ByClass == nil {
		d.ByClass = map[string]int{}
	}
	return &d
}
