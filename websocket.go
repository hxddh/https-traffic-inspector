package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hxddh/https-traffic-inspector/v2/internal/body"
)

// ---- splice ----

// spliceWebSocket performs a WebSocket upgrade handshake with upConn, writes
// the server response to clientW, then splices raw bytes bidirectionally
// between upConn and clientConn until either side closes.
//
// clientConn is the underlying connection (e.g. *tls.Conn) used for the raw
// splice phase. clientW (its bufio wrapper) is only used for the HTTP
// handshake response; raw WebSocket frames bypass it to avoid stale buffering.
//
// When the exchange is being logged (reqID > 0), the handshake response is
// reported like any other, and each message is decoded and reported as it
// passes. Observation never alters or delays the bytes being spliced.
func spliceWebSocket(upConn net.Conn, req *http.Request, clientConn net.Conn, clientW *bufio.Writer, clientR io.Reader, reqID int, f *requestFacts) {
	fail := func(err error) {
		if reqID > 0 {
			logFailure(reqID, f, err)
		}
		writeConnError(clientW, http.StatusBadGateway, err.Error())
		clientW.Flush() //nolint:errcheck
	}
	if err := req.Write(upConn); err != nil {
		fail(err)
		return
	}

	upReader := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upReader, req)
	if err != nil {
		fail(err)
		return
	}
	resp.Body.Close() //nolint:errcheck

	var obs *wsObserver
	if reqID > 0 {
		obs = observeHandshake(reqID, resp)
	}

	if err := resp.Write(clientW); err != nil {
		obs.close()
		return
	}
	if err := clientW.Flush(); err != nil {
		obs.close()
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	// Splice bidirectionally using the raw connection so WebSocket frames are
	// not buffered inside bufio.Writer (which would stall delivery until flush).
	var fromClient, fromServer io.Reader = clientR, upReader
	if obs != nil {
		fromClient = io.TeeReader(clientR, obs.client)
		fromServer = io.TeeReader(upReader, obs.server)
	}
	errc := make(chan struct{}, 2)
	go func() {
		io.Copy(upConn, fromClient) //nolint:errcheck
		upConn.Close()              // signal upstream EOF; unblocks the other goroutine
		errc <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, fromServer) //nolint:errcheck
		clientConn.Close()              // signal client EOF; unblocks goroutine 1
		errc <- struct{}{}
	}()
	<-errc
	<-errc
	obs.close()
}

// ---- observation ----

// wsObserver reports the messages of one WebSocket connection.
type wsObserver struct {
	reqID  int
	facts  *responseFacts
	start  time.Time
	client *wsParser
	server *wsParser

	mu       sync.Mutex
	msgs     []wsMessage // kept for --record and --har, up to maxWSRecorded
	count    int
	closed   bool
	dropped  int
	upgraded bool
}

// maxWSRecorded bounds how many messages of one connection are kept for
// --record and --har; later ones are still shown, and counted.
const maxWSRecorded = 1000

// observeHandshake reports the upgrade response and, for a 101, returns an
// observer for the messages that follow.
func observeHandshake(reqID int, resp *http.Response) *wsObserver {
	f := &responseFacts{
		status:     resp.StatusCode,
		statusText: resp.Status,
		proto:      resp.Proto,
		headers:    resp.Header.Clone(),
		duration:   requestDuration(reqID),
		upgraded:   resp.StatusCode == http.StatusSwitchingProtocols,
	}
	s := currentSink()
	s.responseHead(reqID, f)
	s.responseBody(reqID, f, bodyView{})
	if !f.upgraded {
		captures.addResponse(reqID, capturedResponse{facts: *f})
		return nil
	}

	o := &wsObserver{reqID: reqID, facts: f, start: time.Now(), upgraded: true}
	deflate, clientNoCtx, serverNoCtx := parseDeflateExtension(resp.Header.Values("Sec-WebSocket-Extensions"))
	o.client = &wsParser{fromClient: true, deflate: deflate, noContext: clientNoCtx, onMessage: o.message}
	o.server = &wsParser{fromClient: false, deflate: deflate, noContext: serverNoCtx, onMessage: o.message}
	return o
}

func (o *wsObserver) message(m wsMessage) {
	o.mu.Lock()
	o.count++
	if len(o.msgs) < maxWSRecorded {
		o.msgs = append(o.msgs, m)
	} else {
		o.dropped++
	}
	o.mu.Unlock()
	currentSink().wsMessage(o.reqID, m)
}

// close reports the end of the connection. It is safe on a nil observer.
func (o *wsObserver) close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	msgs, count, dropped := o.msgs, o.count, o.dropped
	o.mu.Unlock()

	sum := wsSummary{messages: count, duration: time.Since(o.start), dropped: dropped}
	currentSink().wsClosed(o.reqID, sum)
	f := *o.facts
	f.duration += sum.duration
	captures.addResponse(o.reqID, capturedResponse{facts: f, ws: msgs, wsDropped: dropped})
}

// parseDeflateExtension reports whether permessage-deflate was negotiated and
// whether each side resets its compression context between messages.
func parseDeflateExtension(values []string) (deflate, clientNoCtx, serverNoCtx bool) {
	for _, v := range values {
		for _, ext := range strings.Split(v, ",") {
			params := strings.Split(ext, ";")
			if strings.TrimSpace(strings.ToLower(params[0])) != "permessage-deflate" {
				continue
			}
			deflate = true
			for _, p := range params[1:] {
				switch strings.TrimSpace(strings.ToLower(p)) {
				case "client_no_context_takeover":
					clientNoCtx = true
				case "server_no_context_takeover":
					serverNoCtx = true
				}
			}
		}
	}
	return
}

// ---- messages ----

const (
	wsContinuation = 0x0
	wsText         = 0x1
	wsBinary       = 0x2
	wsClose        = 0x8
	wsPing         = 0x9
	wsPong         = 0xa
)

// wsMessage is one complete WebSocket message, or one control frame.
type wsMessage struct {
	fromClient  bool
	opcode      byte
	data        []byte // payload, unmasked and decompressed; a prefix when truncated
	size        int64  // payload bytes on the wire
	truncated   bool
	compressed  bool // sent with permessage-deflate; size is the compressed size
	undecodable bool // compressed, but could not be decompressed
	closeCode   int
	closeReason string
	at          time.Time
}

func (m wsMessage) sender() string {
	if m.fromClient {
		return "client"
	}
	return "server"
}

func (m wsMessage) direction() string {
	if m.fromClient {
		return "client→server"
	}
	return "server→client"
}

func (m wsMessage) typeName() string {
	switch m.opcode {
	case wsText:
		return "text"
	case wsBinary:
		return "binary"
	case wsClose:
		return "close"
	case wsPing:
		return "ping"
	case wsPong:
		return "pong"
	}
	return fmt.Sprintf("opcode-%d", m.opcode)
}

// describe is the one-line summary shown in a message's heading.
func (m wsMessage) describe() string {
	if m.opcode == wsClose {
		if m.closeCode == 0 {
			return "close"
		}
		return fmt.Sprintf("close %d %s", m.closeCode, wsCloseName(m.closeCode))
	}
	if m.compressed && !m.undecodable {
		more := ""
		if m.truncated {
			more = "+"
		}
		return fmt.Sprintf("%s (%d%s bytes, %d compressed)", m.typeName(), len(m.data), more, m.size)
	}
	return fmt.Sprintf("%s (%d bytes)", m.typeName(), m.size)
}

// displayText is the message content as shown to the user.
func (m wsMessage) displayText() string {
	switch {
	case m.opcode == wsClose:
		return m.closeReason
	case m.undecodable:
		return fmt.Sprintf("[compressed, %d bytes, not decodable]", m.size)
	case m.opcode == wsText || ((m.opcode == wsPing || m.opcode == wsPong) && utf8.Valid(m.data)):
		return truncateForDisplay(bodyView{Text: string(m.data), Truncated: m.truncated})
	case m.opcode == wsBinary:
		return fmt.Sprintf("[binary, %d bytes]", len(m.data))
	}
	return ""
}

// wsSummary describes a closed WebSocket connection.
type wsSummary struct {
	messages int
	dropped  int
	duration time.Duration
}

func (s wsSummary) describe() string {
	noun := "messages"
	if s.messages == 1 {
		noun = "message"
	}
	return fmt.Sprintf("%d %s in %s", s.messages, noun, s.duration.Round(time.Millisecond))
}

func wsCloseName(code int) string {
	switch code {
	case 1000:
		return "normal"
	case 1001:
		return "going away"
	case 1002:
		return "protocol error"
	case 1003:
		return "unsupported data"
	case 1006:
		return "abnormal"
	case 1007:
		return "invalid payload"
	case 1008:
		return "policy violation"
	case 1009:
		return "message too big"
	case 1010:
		return "extension required"
	case 1011:
		return "internal error"
	}
	return ""
}

// ---- frame parser ----

// wsParser decodes the frames of one direction of a WebSocket connection from
// the bytes the splice relays. It is an io.Writer fed by an io.TeeReader, so
// it sees the stream in order without holding it up; it never fails the
// write, and if the stream stops making sense it simply stops decoding.
type wsParser struct {
	fromClient bool
	deflate    bool // permessage-deflate negotiated
	noContext  bool // this sender resets its compression context per message
	onMessage  func(wsMessage)

	// current frame
	hdr       []byte
	inPayload bool
	remaining int64
	fin       bool
	rsv1      bool
	opcode    byte
	masked    bool
	mask      [4]byte
	maskPos   int

	// message being assembled from data frames
	msgOpcode     byte
	msgCompressed bool
	msgBuf        []byte
	msgSize       int64
	msgTrunc      bool

	ctlBuf []byte

	// window is the sender's recent uncompressed output, which a compressed
	// message may refer back to unless the sender resets context.
	window       []byte
	windowBroken bool

	broken bool
}

const wsDeflateWindow = 32 << 10

func (p *wsParser) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 && !p.broken {
		if !p.inPayload {
			b = p.readHeader(b)
			continue
		}
		take := int64(len(b))
		if take > p.remaining {
			take = p.remaining
		}
		p.payload(b[:take])
		b = b[take:]
		p.remaining -= take
		if p.remaining == 0 {
			p.inPayload = false
			p.frameDone()
		}
	}
	return n, nil
}

// readHeader accumulates frame header bytes and consumes them from b.
func (p *wsParser) readHeader(b []byte) []byte {
	need := 2
	if len(p.hdr) >= 2 {
		need = wsHeaderLen(p.hdr[1])
	}
	for len(p.hdr) < need && len(b) > 0 {
		p.hdr = append(p.hdr, b[0])
		b = b[1:]
		if len(p.hdr) == 2 {
			need = wsHeaderLen(p.hdr[1])
		}
	}
	if len(p.hdr) < need {
		return b
	}

	h := p.hdr
	p.fin = h[0]&0x80 != 0
	p.rsv1 = h[0]&0x40 != 0
	p.opcode = h[0] & 0x0f
	p.masked = h[1]&0x80 != 0
	length := int64(h[1] & 0x7f)
	off := 2
	switch length {
	case 126:
		length = int64(binary.BigEndian.Uint16(h[2:4]))
		off = 4
	case 127:
		l := binary.BigEndian.Uint64(h[2:10])
		if l > 1<<62 {
			p.broken = true
			return nil
		}
		length = int64(l)
		off = 10
	}
	if p.masked {
		copy(p.mask[:], h[off:off+4])
	}
	p.maskPos = 0
	p.hdr = p.hdr[:0]

	if p.opcode >= 0x8 {
		if length > 125 || !p.fin {
			p.broken = true // invalid control frame
			return nil
		}
		p.ctlBuf = p.ctlBuf[:0]
	} else if p.opcode != wsContinuation {
		p.msgOpcode = p.opcode
		p.msgCompressed = p.deflate && p.rsv1
		p.msgBuf = p.msgBuf[:0]
		p.msgSize = 0
		p.msgTrunc = false
	}

	p.remaining = length
	if length == 0 {
		p.frameDone()
		return b
	}
	p.inPayload = true
	return b
}

func wsHeaderLen(b1 byte) int {
	n := 2
	switch b1 & 0x7f {
	case 126:
		n += 2
	case 127:
		n += 8
	}
	if b1&0x80 != 0 {
		n += 4
	}
	return n
}

// payload handles a chunk of the current frame's payload. The chunk belongs to
// the stream being relayed, so it is copied before unmasking.
func (p *wsParser) payload(chunk []byte) {
	if p.opcode >= 0x8 {
		p.ctlBuf = p.appendUnmasked(p.ctlBuf, chunk, len(chunk))
		return
	}
	p.msgSize += int64(len(chunk))
	room := captureMaxBody - len(p.msgBuf)
	if room < len(chunk) {
		p.msgTrunc = true
	}
	if room < 0 {
		room = 0
	}
	p.msgBuf = p.appendUnmasked(p.msgBuf, chunk, room)
}

// appendUnmasked appends up to max bytes of chunk to dst, unmasked, and
// advances the mask position past the whole chunk.
func (p *wsParser) appendUnmasked(dst, chunk []byte, max int) []byte {
	if max > len(chunk) {
		max = len(chunk)
	}
	start := len(dst)
	dst = append(dst, chunk[:max]...)
	if p.masked {
		for i := start; i < len(dst); i++ {
			dst[i] ^= p.mask[(p.maskPos+i-start)%4]
		}
	}
	p.maskPos = (p.maskPos + len(chunk)) % 4
	return dst
}

func (p *wsParser) frameDone() {
	now := time.Now()
	if p.opcode >= 0x8 {
		m := wsMessage{fromClient: p.fromClient, opcode: p.opcode, data: append([]byte(nil), p.ctlBuf...), size: int64(len(p.ctlBuf)), at: now}
		if p.opcode == wsClose && len(p.ctlBuf) >= 2 {
			m.closeCode = int(binary.BigEndian.Uint16(p.ctlBuf[:2]))
			m.closeReason = string(p.ctlBuf[2:])
		}
		p.onMessage(m)
		return
	}
	if !p.fin {
		return
	}
	m := wsMessage{fromClient: p.fromClient, opcode: p.msgOpcode, size: p.msgSize, truncated: p.msgTrunc, at: now}
	data := append([]byte(nil), p.msgBuf...)
	if p.msgCompressed {
		m.compressed = true
		data, m.truncated, m.undecodable = p.inflate(data, p.msgTrunc)
	}
	m.data = data
	p.onMessage(m)
}

// inflate decompresses one permessage-deflate message. With context takeover
// the sender's LZ77 window spans messages, so the recent uncompressed output
// is supplied as the dictionary.
func (p *wsParser) inflate(data []byte, partial bool) (out []byte, truncated, undecodable bool) {
	if p.windowBroken && !p.noContext {
		return nil, false, true
	}
	if partial {
		// Without the whole message the window cannot be kept in step.
		p.windowBroken = true
	}
	dict := p.window
	if p.noContext {
		dict = nil
	}
	src := io.MultiReader(bytes.NewReader(data), bytes.NewReader([]byte{0, 0, 0xff, 0xff}))
	r := flate.NewReaderDict(src, dict)
	out, err := io.ReadAll(io.LimitReader(r, body.MaxDecompressed))
	// The message ends with a sync flush, not a final block, so running out
	// of input is the normal way for it to end.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		if len(out) == 0 {
			p.windowBroken = true
			return nil, false, true
		}
		partial = true
	}
	if !p.noContext && !partial {
		w := append(p.window, out...)
		if len(w) > wsDeflateWindow {
			w = w[len(w)-wsDeflateWindow:]
		}
		p.window = append([]byte(nil), w...)
	}
	if len(out) > captureMaxBody {
		out, partial = out[:captureMaxBody], true
	}
	return out, partial, false
}
