//go:build unix

// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func tryCustodyFileLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return false, nil
	}
	return err == nil, err
}

func unlockCustodyFile(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
