//go:build !windows

package registry

import (
	"errors"
	"syscall"
)

// alive reports whether pid exists. A process we may not signal (EPERM)
// still counts as alive.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
