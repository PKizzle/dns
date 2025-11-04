//go:build windows
// +build windows

package log

import (
	"os"
)

var (
	USR_SIGNAL = os.Interrupt
)
