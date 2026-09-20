// SPDX-License-Identifier: BUSL-1.1

// Package fsatomic holds the small filesystem-durability helpers an
// atomic-replace write needs. A write-then-rename is only crash-safe when the
// file's CONTENTS are durable before the rename and the DIRECTORY ENTRY is
// durable after it; skipping either lets a power loss commit a rename whose
// target is empty or torn. The helpers live in one stdlib-only package so the
// signer keystore, the sign journal, and the transit keyring share a single
// copy of the pattern instead of each hand-rolling it (AUD-201 follow-up
// B4/V5).
package fsatomic

import "os"

// SyncDirectory makes a create/rename directory entry durable, not merely the
// file contents. Without it, a power loss can forget the rename even though
// the file's own Sync succeeded.
func SyncDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- the caller's own state directory (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
