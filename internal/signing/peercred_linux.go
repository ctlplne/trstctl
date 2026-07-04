// SPDX-License-Identifier: MPL-2.0

//go:build linux

package signing

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a Unix domain
// socket connection via SO_PEERCRED.
func peerUID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		uid     int
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			credErr = e
			return
		}
		uid = int(ucred.Uid)
	}); err != nil || credErr != nil {
		return 0, false
	}
	return uid, true
}

func peerCredentialsSupported() bool { return true }
