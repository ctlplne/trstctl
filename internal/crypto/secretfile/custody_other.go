// SPDX-License-Identifier: BUSL-1.1

//go:build !unix && !windows

package secretfile

import (
	"fmt"
	"os"
)

func validateNonUnixParent(string, os.FileInfo) error { return nil }
func validateNonUnixFile(path string, _ os.FileInfo) error {
	return fmt.Errorf("secretfile: %s custody is unsupported on this platform", path)
}
func securePrivateDirectoryPermissions(string) error { return errorsUnsupportedCustody() }
func securePrivateFilePermissions(string) error      { return errorsUnsupportedCustody() }
func securePublicFilePermissions(string) error       { return errorsUnsupportedCustody() }
func privateFilePermissions(string, os.FileInfo) (bool, error) {
	return false, errorsUnsupportedCustody()
}
func publicFilePermissions(string, os.FileInfo) (bool, error) {
	return false, errorsUnsupportedCustody()
}
func errorsUnsupportedCustody() error {
	return fmt.Errorf("secretfile: filesystem custody is unsupported on this platform")
}
