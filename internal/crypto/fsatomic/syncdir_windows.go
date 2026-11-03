// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package fsatomic

// Windows does not expose a directory handle that os.File.Sync can flush
// (os.Open + Sync on a directory answers "Access is denied"). The file itself
// is flushed before publication, so only the directory-entry flush is omitted.
func syncDirectory(string) error { return nil }
