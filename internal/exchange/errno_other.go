//go:build !windows

package exchange

import "syscall"

// Only Winsock needs numbers of its own; elsewhere the syscall constants match.
var (
	refusedErrnos []syscall.Errno
	resetErrnos   []syscall.Errno
)
