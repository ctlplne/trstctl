//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"errors"
	"os"
	"syscall"
)

func tryLockSignerCustody(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return errKeyStoreLockBusy
	}
	return err
}
