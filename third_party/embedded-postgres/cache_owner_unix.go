// SPDX-License-Identifier: MIT
//go:build unix

package embeddedpostgres

import (
	"fmt"
	"os"
	"syscall"
)

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && fmt.Sprint(stat.Uid) == fmt.Sprint(os.Geteuid())
}

func ownedByTrustedTempUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || ownedByCurrentUser(info))
}

func openRegularFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
