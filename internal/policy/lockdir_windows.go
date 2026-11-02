//go:build windows

package policy

// lockDir is a no-op on Windows: edits are still atomic, only not
// serialised against each other.
func lockDir(string) (func(), error) { return func() {}, nil }
