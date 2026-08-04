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
// This replaces reading a fixed prefix with io.ReadFull. ReadFull only returns
// once the buffer is full or the stream ends, so a body that trickles — an SSE
// feed, a chunked upload, a slow download — was withheld in full until the far
// end closed. Sampling alongside the copy keeps delivery immediate.
type bodySampler struct {
	rc     io.ReadCloser
	limit  int
	onDone func(raw []byte, overflow bool)

	mu       sync.Mutex
	buf      bytes.Buffer
	overflow bool
	fired    bool
}

func newBodySampler(rc io.ReadCloser, limit int, onDone func(raw []byte, overflow bool)) *bodySampler {
	return &bodySampler{rc: rc, limit: limit, onDone: onDone}
}

func (s *bodySampler) Read(p []byte) (int, error) {
	n, err := s.rc.Read(p)
	if n > 0 {
		s.mu.Lock()
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
		s.fire()
	}
	return n, err
}

func (s *bodySampler) Close() error {
	s.fire()
	return s.rc.Close()
}

// fire delivers the sample once, whether the body ended in EOF, an error, or a
// Close by a consumer that stopped reading early.
func (s *bodySampler) fire() {
	s.mu.Lock()
	if s.fired {
		s.mu.Unlock()
		return
	}
	s.fired = true
	raw := make([]byte, s.buf.Len())
	copy(raw, s.buf.Bytes())
	overflow := s.overflow
	cb := s.onDone
	s.mu.Unlock()

	if cb != nil {
		cb(raw, overflow)
	}
}

// sampleBody installs a sampler on *bodyp and returns. onDone is invoked when
// the body completes — immediately when there is no body at all, so callers can
// rely on it firing exactly once.
func sampleBody(bodyp *io.ReadCloser, h http.Header, onDone func(bodyView)) {
	limit := captureLimitFor(h)

	if bodyp == nil || *bodyp == nil {
		onDone(bodyView{})
		return
	}
	*bodyp = newBodySampler(*bodyp, limit, func(raw []byte, overflow bool) {
		onDone(decodeBody(h, raw, overflow))
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
// Content-Encoding when possible. overflow reports that more data followed the
// captured prefix.
func decodeBody(h http.Header, raw []byte, overflow bool) bodyView {
	if len(raw) == 0 {
		return bodyView{}
	}

	enc := h.Get("Content-Encoding")
	compressed := len(splitEncodings(enc)) > 0

	if !compressed {
		if isPrintableContentType(h.Get("Content-Type")) {
			return bodyView{Text: string(raw), Truncated: overflow}
		}
		return bodyView{Text: binaryPlaceholder(raw)}
	}

	res, err := decompressBody(enc, raw)
	if err == nil && isPrintableContentType(h.Get("Content-Type")) {
		return bodyView{Text: string(res.Data), Truncated: res.Truncated || overflow}
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
