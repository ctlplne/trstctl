// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package connector

import "os"

func syncLocalDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- path is the parent of an operator-approved local connector target (CWE-22)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
