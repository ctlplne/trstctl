//go:build windows

// SPDX-License-Identifier: BUSL-1.1

package reportstate

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

// Windows flushes the state file before its atomic rename. It does not expose
// Unix directory fsync; process-restart recovery is supported, while durability
// through machine power loss requires native filesystem qualification.
func syncDirectory(*os.Root) error { return nil }
