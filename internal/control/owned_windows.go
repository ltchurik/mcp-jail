//go:build windows

package control

import "os"

func ownedDir(dir string) error { return os.MkdirAll(dir, 0o700) }
