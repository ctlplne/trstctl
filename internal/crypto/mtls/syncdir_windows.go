// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package mtls

// Windows does not expose a directory handle that os.File.Sync can flush. The
// file itself is flushed before publication, so omit only the unavailable
// directory-entry flush.
func syncMTLSDirectory(string) error { return nil }
