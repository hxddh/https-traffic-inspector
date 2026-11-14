package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"unicode/utf8"

	"github.com/hxddh/https-traffic-inspector/v3/internal/body"
)

// bodySampler wraps a body so its content can be logged without holding up
// delivery. Bytes are copied into an internal buffer, capped at limit, as the
// consumer reads them; onDone fires exactly once when the body ends.
//
// incomplete reports that the body stopped short of its end: capture overflowed
// the limit, the stream failed, or the consumer closed it before EOF (a client
// that disconnected mid-download). Either way the sample is only a prefix.
//
// This replaces reading a fixed prefix with io.ReadFull. ReadFull only returns
// once the buffer is full or the stream ends, so a body that trickles — an SSE
// feed, a chunked upload, a slow download — was withheld in full until the far
// end closed. Sampling alongside the copy keeps delivery immediate.
type bodySampler struct {
	rc     io.ReadCloser
	limit  int
	expect int64 // declared length, or -1 when unknown
	onDone func(raw []byte, incomplete bool, total int64)

	mu       sync.Mutex
	buf      bytes.Buffer
	total    int64
	overflow bool
	fired    bool
}

func newBodySampler(rc io.ReadCloser, limit int, expect int64, onDone func(raw []byte, incomplete bool, total int64)) *bodySampler {
	return &bodySampler{rc: rc, limit: limit, expect: expect, onDone: onDone}
}

func (s *bodySampler) Read(p []byte) (int, error) {
	n, err := s.rc.Read(p)
	if n > 0 {
		s.mu.Lock()
		s.total += int64(n)
		if room := s.limit - s.buf.Len(); room > 0 {
			if n <= room {
				s.buf.Write(p[:n])
			} else {
				s.buf.Write(p[:room])
				s.overflow = true
			}
		} else {
			s.overflow = true
		}
		s.mu.Unlock()
	}
	if err != nil {
		s.fire(err == io.EOF)
	}
	return n, err
}

func (s *bodySampler) Close() error {
	s.fire(false) // a no-op if EOF was already seen
	return s.rc.Close()
}

// fire delivers the sample once, whether the body ended in EOF, an error, or a
// Close by a consumer that stopped reading early.
func (s *bodySampler) fire(reachedEOF bool) {
	s.mu.Lock()
	if s.fired {
		s.mu.Unlock()
		return
	}
	s.fired = true
	raw := make([]byte, s.buf.Len())
	copy(raw, s.buf.Bytes())
	// A body that delivered its whole declared length is complete even if
	// its consumer stopped before reading EOF.
	whole := reachedEOF || (s.expect >= 0 && s.total == s.expect)
	incomplete := s.overflow || !whole
	total := s.total
	cb := s.onDone
	s.mu.Unlock()

	if cb != nil {
		cb(raw, incomplete, total)
	}
}

// sampleBody installs a sampler on *bodyp and returns. onDone is invoked when
// the body completes — immediately when there is no body at all, so callers can
// rely on it firing exactly once.
func sampleBody(bodyp *io.ReadCloser, h http.Header, length int64, onDone func(bodyView)) {
	sampleBodyFor(bodyp, h, length, captureLimitFor(h, 0, false), onDone)
}

// sampleRequestBody and sampleResponseBody keep only as much of a body as
// the active outputs need.
func sampleRequestBody(bodyp *io.ReadCloser, h http.Header, length int64, onDone func(bodyView)) {
	sampleBodyFor(bodyp, h, length, captureLimitFor(h, 0, true), onDone)
}

func sampleResponseBody(bodyp *io.ReadCloser, h http.Header, length int64, status int, onDone func(bodyView)) {
	sampleBodyFor(bodyp, h, length, captureLimitFor(h, status, false), onDone)
}

func sampleBodyFor(bodyp *io.ReadCloser, h http.Header, length int64, limit int, onDone func(bodyView)) {
	// http.NoBody must stay as it is. Wrapped, it no longer reads as empty to
	// the transport, which then forwards a Content-Length: 0 POST or PUT as
	// Transfer-Encoding: chunked -- a request S3 and others reject.
	if bodyp == nil || *bodyp == nil || *bodyp == http.NoBody {
		onDone(bodyView{})
		return
	}
	*bodyp = newBodySampler(*bodyp, limit, length, func(raw []byte, incomplete bool, total int64) {
		v := decodeBody(h, raw, incomplete)
		v.Raw, v.RawTruncated, v.Size = raw, incomplete, total
		onDone(v)
	})
}

// captureLimitFor reports how many bytes of a body to keep, which depends on
// what the active outputs will do with it. Keeping a full capture of every
// body made the summary -- the default off a terminal -- use nearly seven
// times the memory of the text output for parallel downloads, although it
// shows no body at all.
//
//   - --record and --har store the bytes: up to --max-capture.
//   - Text and the TUI show a prefix: --max-body, or --max-capture for a
//     compressed body, which must be decoded from its start.
//   - The summary only reads an error response's JSON for its code.
//   - JSON parses JSON and gRPC bodies, shows a prefix of text, and gives
//     only the size of anything else.
func captureLimitFor(h http.Header, status int, isRequest bool) int {
	if recordMode || harMode {
		return captureMaxBody
	}
	ct := h.Get("Content-Type")
	encoded := len(body.SplitEncodings(h.Get("Content-Encoding"))) > 0
	switch {
	case summaryMode && !tuiMode:
		if !isRequest && status >= 400 && (ct == "" || body.LooksLikeJSONType(ct)) {
			return captureMaxBody
		}
		return 0
	case jsonMode && !tuiMode:
		switch {
		case ct == "" || body.LooksLikeJSONType(ct) || body.IsGRPC(ct):
			return captureMaxBody
		case body.PrintableType(ct):
			if encoded {
				return captureMaxBody
			}
			return displayMaxBody
		}
		return 0
	}
	if encoded {
		return captureMaxBody
	}
	return displayMaxBody
}

// decodeBody turns captured bytes into a printable view, decoding
// Content-Encoding when possible. incomplete reports that raw is only a prefix
// of the body.
func decodeBody(h http.Header, raw []byte, incomplete bool) bodyView {
	if len(raw) == 0 {
		return bodyView{}
	}

	if body.IsGRPC(h.Get("Content-Type")) {
		return bodyView{Text: body.GRPCSummary(raw, incomplete), Truncated: incomplete}
	}

	enc := h.Get("Content-Encoding")
	compressed := len(body.SplitEncodings(enc)) > 0

	if !compressed {
		if looksLikeText(h.Get("Content-Type"), raw, incomplete) {
			return bodyView{Text: string(raw), Truncated: incomplete}
		}
		return bodyView{Text: binaryPlaceholder(raw)}
	}

	// This view is only shown, never stored, so decoding stops just past what
	// can be shown: the rest would be thrown away.
	res, err := body.DecompressLimit(enc, raw, displayMaxBody+utf8.UTFMax)
	if err == nil && isPrintableContentType(h.Get("Content-Type")) {
		return bodyView{Text: string(res.Data), Truncated: res.Truncated || incomplete}
	}
	return bodyView{Text: encodedPlaceholder(enc, raw)}
}

// looksLikeText reports whether an uncompressed body should be shown as text.
// A body with no Content-Type is judged by its bytes: printed blindly, a
// binary download would fill the screen with escaped noise.
func looksLikeText(ct string, raw []byte, incomplete bool) bool {
	if !isPrintableContentType(ct) {
		return false
	}
	if ct != "" {
		return true
	}
	if incomplete {
		// The capture may have cut a multi-byte character in half.
		for i := 0; i < 3 && len(raw) > 0 && !utf8.Valid(raw); i++ {
			raw = raw[:len(raw)-1]
		}
	}
	return utf8.Valid(raw)
}

// binaryPlaceholder describes a body that is not worth printing as text.
func binaryPlaceholder(raw []byte) string {
	return fmt.Sprintf("[binary data, %d+ bytes]", len(raw))
}

// encodedPlaceholder describes a body whose Content-Encoding could not be
// decoded. Printing the still-encoded bytes would render as garbage.
func encodedPlaceholder(enc string, raw []byte) string {
	return fmt.Sprintf("[%s, %d+ bytes]", enc, len(raw))
}

// flushWriter pushes each write through to the wire immediately. A
// bufio.Writer on its own holds data until its buffer fills, so a streaming
// body would sit in the buffer until the stream ended even though the body is
// no longer being read up front.
type flushWriter struct {
	w     io.Writer
	flush func() error
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err != nil {
		return n, err
	}
	if f.flush != nil {
		if err := f.flush(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// copyFlushing forwards src to dst, flushing after each write so a streaming
// body reaches the client as it arrives.
func copyFlushing(dst io.Writer, src io.Reader, fl http.Flusher) error {
	target := dst
	if fl != nil {
		target = flushWriter{w: dst, flush: func() error { fl.Flush(); return nil }}
	}
	_, err := io.Copy(target, src)
	return err
}
