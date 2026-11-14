//go:build windows

package session

import "os"

// processAlive reports whether a process with this pid exists. On Windows,
// FindProcess opens a handle and fails when there is no such process.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	p.Release() //nolint:errcheck
	return true
}
