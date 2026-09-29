package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
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
	onDone func(raw []byte, incomplete bool)

	mu       sync.Mutex
	buf      bytes.Buffer
	total    int64
	overflow bool
	fired    bool
}

func newBodySampler(rc io.ReadCloser, limit int, expect int64, onDone func(raw []byte, incomplete bool)) *bodySampler {
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
	cb := s.onDone
	s.mu.Unlock()

	if cb != nil {
		cb(raw, incomplete)
	}
}

// sampleBody installs a sampler on *bodyp and returns. onDone is invoked when
// the body completes — immediately when there is no body at all, so callers can
// rely on it firing exactly once.
func sampleBody(bodyp *io.ReadCloser, h http.Header, length int64, onDone func(bodyView)) {
	limit := captureLimitFor(h)

	// http.NoBody must stay as it is. Wrapped, it no longer reads as empty to
	// the transport, which then forwards a Content-Length: 0 POST or PUT as
	// Transfer-Encoding: chunked -- a request S3 and others reject.
	if bodyp == nil || *bodyp == nil || *bodyp == http.NoBody {
		onDone(bodyView{})
		return
	}
	*bodyp = newBodySampler(*bodyp, limit, length, func(raw []byte, incomplete bool) {
		onDone(decodeBody(h, raw, incomplete))
	})
}

// captureLimitFor reports how many bytes of a body to retain. Recording, HAR
// export and decompression all need more than the display limit.
func captureLimitFor(h http.Header) int {
	if recordMode || harMode || len(splitEncodings(h.Get("Content-Encoding"))) > 0 {
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

	if isGRPCContentType(h.Get("Content-Type")) {
		return bodyView{Text: grpcSummary(raw, incomplete), Truncated: incomplete}
	}

	enc := h.Get("Content-Encoding")
	compressed := len(splitEncodings(enc)) > 0

	if !compressed {
		if isPrintableContentType(h.Get("Content-Type")) {
			return bodyView{Text: string(raw), Truncated: incomplete}
		}
		return bodyView{Text: binaryPlaceholder(raw)}
	}

	res, err := decompressBody(enc, raw)
	if err == nil && isPrintableContentType(h.Get("Content-Type")) {
		return bodyView{Text: string(res.Data), Truncated: res.Truncated || incomplete}
	}
	return bodyView{Text: encodedPlaceholder(enc, raw)}
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
