// SPDX-License-Identifier: BUSL-1.1

//go:build !unix

package secretfile

import "os"

type owner struct {
	uid int
	gid int
}

func fileOwner(os.FileInfo) (owner, bool) {
	return owner{}, false
}

func supportsUnixModeCustody() bool {
	return false
}
