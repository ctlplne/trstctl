// SPDX-License-Identifier: BUSL-1.1

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package privatesocket

import (
	"errors"
	"os"
	"syscall"
)

func ownerUID(info os.FileInfo) (int, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("socket path owner is unavailable")
	}
	return int(st.Uid), nil
}
