// SPDX-License-Identifier: BUSL-1.1

// Package fsatomic holds the small filesystem-durability helpers an
// atomic-replace write needs. A write-then-rename is only crash-safe when the
// file's CONTENTS are durable before the rename and the DIRECTORY ENTRY is
// durable after it; skipping either lets a power loss commit a rename whose
// target is empty or torn. The helpers live in one stdlib-only package so the
// signer keystore, the sign journal, and the transit keyring share a single
// copy of the pattern instead of each hand-rolling it (AUD-201 follow-up
// B4/V5). It sits inside the crypto boundary so packages there, such as
// samltest, can use it too (AN-3 lets them import nothing from outside).
package fsatomic

// SyncDirectory makes a create/rename directory entry durable, not merely the
// file contents. Without it, a power loss can forget the rename even though
// the file's own Sync succeeded. Windows exposes no directory handle that
// os.File.Sync can flush, so there it does nothing; callers flush each file
// before its rename or link, as mtls and connector already do on Windows
// (owner decision 2026-11-02, item 2g c).
func SyncDirectory(path string) error { return syncDirectory(path) }
