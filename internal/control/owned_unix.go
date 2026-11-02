//go:build !windows

package control

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ownedDir creates dir with mode 0700 or verifies that an existing one is a
// real directory owned by this user and not accessible to others.
func ownedDir(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("%s: not a directory", dir)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: accessible to other users (mode %o)", dir, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s: owned by uid %d, not us", dir, sys.Uid)
	}
	return nil
}
