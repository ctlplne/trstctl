// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"errors"
	"os"
)

// allowReplace lets the rename replace an earlier rendered file. Windows maps
// a mode without write bits to the read-only attribute, and a rename can't
// replace a read-only destination, so the attribute is cleared first; the new
// file carries it again.
func allowReplace(path string) error {
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
