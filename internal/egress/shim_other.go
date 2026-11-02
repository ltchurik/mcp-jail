//go:build !linux

package egress

import "errors"

func runServer([]string, int, int) (int, error) {
	return 1, errors.New("egress shim is only used inside a Linux jail")
}
