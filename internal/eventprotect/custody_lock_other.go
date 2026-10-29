//go:build !unix && !windows

// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"errors"
	"os"
)

func tryCustodyFileLock(*os.File) (bool, error) {
	return false, errors.New("eventprotect: independent file custody locking is unavailable on this platform")
}
func unlockCustodyFile(*os.File) error { return nil }
