//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// SPDX-License-Identifier: BUSL-1.1

package reportstate

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func syncDirectory(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
