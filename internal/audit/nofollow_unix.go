//go:build !windows

package audit

import "syscall"

const noFollow = syscall.O_NOFOLLOW
