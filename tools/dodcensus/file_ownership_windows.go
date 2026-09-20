//go:build windows

// SPDX-License-Identifier: BUSL-1.1

package main

import "os"

// Windows does not expose Unix UID/GID/link identity through os.FileInfo. The
// DOD runtime is pinned to Linux, so a Windows execution must fail these
// ownership checks closed while the package remains available to build/vet.
func fileOwnership(os.FileInfo) (uid, gid uint32, links uint64, ok bool) {
	return 0, 0, 0, false
}
