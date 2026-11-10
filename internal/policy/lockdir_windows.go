//go:build windows

package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// lockDir serialises edits on Windows, which has no flock: a lock file
// created exclusively next to the policy, retried until the other editor
// removes it. A lock older than lockStale (an editor that died) is taken
// over, so a crash cannot wedge every later edit.
const lockStale = 30 * time.Second

func lockDir(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, ".mcp-jail.lock")
	deadline := time.Now().Add(lockStale + 5*time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		// ERROR_ACCESS_DENIED is what Windows answers while another
		// editor's unlock (the delete) is still pending: busy, not ours.
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, os.ErrPermission) {
			return nil, err
		}
		last := err
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) > lockStale {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: held by another editor for too long (%v)", path, last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
