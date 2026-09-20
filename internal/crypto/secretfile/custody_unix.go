// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package secretfile

import (
	"fmt"
	"os"
)

func validateNonUnixParent(string, os.FileInfo) error { return nil }
func validateNonUnixFile(string, os.FileInfo) error   { return nil }

func securePrivateDirectoryPermissions(path string) error {
	// #nosec G302 -- this is a directory; owner execute is required to traverse it, and 0700 grants nothing to group/other (CWE-276)
	return os.Chmod(path, 0o700)
}

func securePrivateFilePermissions(path string) error { return os.Chmod(path, 0o600) }

func securePublicFilePermissions(path string) error {
	// #nosec G302 -- this is public certificate/trust material; group/other may read it but only the owner may write it (CWE-276)
	return os.Chmod(path, 0o644)
}

func privateFilePermissions(_ string, info os.FileInfo) (bool, error) {
	perm := info.Mode().Perm()
	return perm&0o077 == 0 && perm&0o400 != 0 && perm&0o111 == 0, nil
}

func publicFilePermissions(_ string, info os.FileInfo) (bool, error) {
	perm := info.Mode().Perm()
	if perm&0o022 != 0 {
		return false, nil
	}
	if perm&0o444 == 0 {
		return false, fmt.Errorf("secretfile: public certificate is not readable")
	}
	return true, nil
}
