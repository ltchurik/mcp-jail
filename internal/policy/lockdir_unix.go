//go:build !windows

package policy

import (
	"os"
	"syscall"
)

// lockDir takes an exclusive advisory lock on dir for the duration of an
// edit. The directory is never renamed, unlike the policy file, so every
// editor contends on the same lock.
func lockDir(dir string) (unlock func(), err error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
