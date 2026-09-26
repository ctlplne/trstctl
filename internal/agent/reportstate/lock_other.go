//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

// SPDX-License-Identifier: BUSL-1.1

package reportstate

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("reportstate: process locking is unavailable on this operating system")
}
func syncDirectory(*os.Root) error {
	return errors.New("reportstate: directory durability is unavailable on this operating system")
}
