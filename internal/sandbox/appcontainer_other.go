//go:build !windows

package sandbox

import "errors"

// RunAppContainer is the Windows launcher; elsewhere it is never reached.
func RunAppContainer(AppContainerOptions, func(string, ...any)) (int, error) {
	return 2, errors.New("appcontainer: only on Windows")
}

// RootStatNotes is a Windows check; nothing to say elsewhere.
func RootStatNotes([]string, string) []string { return nil }
