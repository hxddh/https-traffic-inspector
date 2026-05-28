package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// spliceWebSocket performs a WebSocket upgrade handshake with upConn, writes
// the server response to clientW, then splices raw bytes bidirectionally
// between upConn and clientConn until either side closes.
//
// clientConn is the underlying connection (e.g. *tls.Conn) used for the raw
// splice phase. clientW (its bufio wrapper) is only used for the HTTP
// handshake response; raw WebSocket frames bypass it to avoid stale buffering.
func spliceWebSocket(upConn net.Conn, req *http.Request, clientConn net.Conn, clientW *bufio.Writer, clientR io.Reader) {
	if err := req.Write(upConn); err != nil {
		writeConnError(clientW, http.StatusBadGateway, err.Error())
		clientW.Flush() //nolint:errcheck
		return
	}

	upReader := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upReader, req)
	if err != nil {
		writeConnError(clientW, http.StatusBadGateway, err.Error())
		clientW.Flush() //nolint:errcheck
		return
	}
	resp.Body.Close()

	if err := resp.Write(clientW); err != nil {
		return
	}
	if err := clientW.Flush(); err != nil {
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	// Splice bidirectionally using the raw connection so WebSocket frames are
	// not buffered inside bufio.Writer (which would stall delivery until flush).
	errc := make(chan struct{}, 2)
	go func() {
		io.Copy(upConn, clientR) //nolint:errcheck
		upConn.Close()           // signal upstream EOF; unblocks the other goroutine
		errc <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upReader) //nolint:errcheck
		errc <- struct{}{}
	}()
	<-errc
	<-errc
}
