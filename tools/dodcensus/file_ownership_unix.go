//go:build !windows

// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"syscall"
)

func fileOwnership(info os.FileInfo) (uid, gid uint32, links uint64, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return stat.Uid, stat.Gid, uint64(stat.Nlink), true
}
