// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package mtls

import "os"

func syncMTLSDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- parent of a validated internal TLS state path (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
