// SPDX-License-Identifier: MPL-2.0

//go:build unix

package secretfile

import (
	"os"
	"syscall"
)

type owner struct {
	uid int
	gid int
}

func fileOwner(info os.FileInfo) (owner, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return owner{}, false
	}
	return owner{uid: int(st.Uid), gid: int(st.Gid)}, true
}

func supportsUnixModeCustody() bool {
	return true
}
