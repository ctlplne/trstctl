// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package connector

// Windows does not expose a directory handle that os.File.Sync can flush.
// Credential bytes are flushed before the atomic rename; only the unsupported
// directory-entry flush is omitted here.
func syncLocalDirectory(string) error { return nil }
