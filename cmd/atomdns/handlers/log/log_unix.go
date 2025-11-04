//go:build !windows
// +build !windows

package log

import "syscall"

const USR_SIGNAL = syscall.SIGUSR1
