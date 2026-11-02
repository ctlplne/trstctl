// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceRetryBudget bounds how long a busy destination is retried, as the Go
// toolchain's own robustio does for the same Windows behavior.
const replaceRetryBudget = 2 * time.Second

// replaceFile renames tmp over path. Windows refuses to replace a read-only
// file, so the attribute is cleared first (the new file carries it again). It
// also refuses while another process has the file open without delete sharing,
// as an application reading its secrets file does, so a busy destination is
// retried briefly. If the replace still fails, the earlier file keeps its mode
// and the next render tries again.
func replaceFile(tmp, path string, mode os.FileMode) error {
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err := os.Rename(tmp, path)
	for delay, waited := time.Millisecond, time.Duration(0); err != nil && replaceBusy(err) && waited < replaceRetryBudget; delay *= 2 {
		time.Sleep(delay)
		waited += delay
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Chmod(path, mode)
	}
	return err
}

func replaceBusy(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
