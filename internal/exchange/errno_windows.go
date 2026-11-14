//go:build windows

package exchange

import "syscall"

// Winsock reports connection failures with its own error numbers, which are
// not syscall.ECONNREFUSED and syscall.ECONNRESET.
var (
	refusedErrnos = []syscall.Errno{10061}        // WSAECONNREFUSED
	resetErrnos   = []syscall.Errno{10053, 10054} // WSAECONNABORTED, WSAECONNRESET
)
