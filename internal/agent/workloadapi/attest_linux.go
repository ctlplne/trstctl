// SPDX-License-Identifier: MPL-2.0

//go:build linux

package workloadapi

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// peerCredentialsFD reads SO_PEERCRED, which carries pid, uid and gid together.
func peerCredentialsFD(fd uintptr) (PeerIdentity, error) {
	cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("workloadapi: read peer credentials: %w", err)
	}
	return PeerIdentity{PID: int(cred.Pid), UID: int(cred.Uid), GID: int(cred.Gid)}, nil
}
