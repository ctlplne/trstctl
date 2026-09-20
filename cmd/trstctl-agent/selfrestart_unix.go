// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// restartSelf replaces this process with the (just-staged) binary at its own
// path (epic A5). Exec keeps the PID, so systemd/launchd see a process that
// never exited — the cleanest possible restart for a supervised agent, and for
// an interactive one it is exactly "the agent restarted itself".
//
// The executed job report is delivered BEFORE this runs; exec never returns.
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ()) // #nosec G204 G702 -- re-exec of this process's OWN executable path with its own args; the binary at that path was just digest-verified against the campaign's pinned sha256 (CWE-78)
}
