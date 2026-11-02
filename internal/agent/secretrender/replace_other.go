// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package secretrender

import "os"

// replaceFile renames tmp over path; a rename replaces a file whatever its
// mode, and readers holding the old file keep reading it.
func replaceFile(tmp, path string, _ os.FileMode) error { return os.Rename(tmp, path) }
