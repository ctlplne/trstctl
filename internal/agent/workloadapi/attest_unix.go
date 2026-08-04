// SPDX-License-Identifier: MPL-2.0

//go:build linux || darwin

package workloadapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentials asks the kernel who is on the other end of the socket.
//
// This is the whole trust anchor of local attestation. Everything the selectors
// assert traces back to these three numbers, and they come from the kernel's
// record of the connecting process rather than from anything that process said.
func peerCredentials(conn *net.UnixConn) (PeerIdentity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("workloadapi: access socket: %w", err)
	}
	var (
		id       PeerIdentity
		innerErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		id, innerErr = peerCredentialsFD(fd)
	})
	if ctrlErr != nil {
		return PeerIdentity{}, fmt.Errorf("workloadapi: control socket: %w", ctrlErr)
	}
	if innerErr != nil {
		return PeerIdentity{}, innerErr
	}
	return id, nil
}

var _ = unix.SOL_SOCKET
