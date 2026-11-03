// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package fsatomic

import "os"

func syncDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- the caller's own state directory (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
