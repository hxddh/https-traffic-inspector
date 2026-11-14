//go:build windows

package session

import "syscall"

const (
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
)

// processAlive reports whether a process with this pid is running. A handle
// can be opened to a process that has exited while others hold one, so its
// exit code is checked too.
func processAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid)) //nolint:gosec // pids fit
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h) //nolint:errcheck
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
