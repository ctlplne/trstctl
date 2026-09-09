// SPDX-License-Identifier: MIT
//go:build !unix

package embeddedpostgres

import "os"

// No served archive is pinned for these platforms. Do not silently omit the
// ownership check if another caller supplies an identity there.
func ownedByCurrentUser(_ os.FileInfo) bool { return false }

func ownedByTrustedTempUser(_ os.FileInfo) bool { return false }

func openRegularFile(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
