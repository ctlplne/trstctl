// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package secretrender

import (
	"strings"
	"syscall"
)

// signalProcess sends a reload signal to the application's process.
func signalProcess(pid int, name string) error {
	sig := syscall.SIGHUP
	switch strings.TrimPrefix(strings.ToUpper(name), "SIG") {
	case "USR1":
		sig = syscall.SIGUSR1
	case "USR2":
		sig = syscall.SIGUSR2
	case "TERM":
		sig = syscall.SIGTERM
	}
	return syscall.Kill(pid, sig)
}
