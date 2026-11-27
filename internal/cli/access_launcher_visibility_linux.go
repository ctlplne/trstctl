// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package cli

import "golang.org/x/sys/unix"

// protectLauncherProcess denies same-user process inspection while a
// delegated command runs. The CLI is one-shot, so the setting stays in force.
func protectLauncherProcess() (bool, error) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return false, err
	}
	return true, nil
}
