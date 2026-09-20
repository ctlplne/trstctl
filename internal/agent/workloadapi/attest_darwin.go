// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package workloadapi

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// peerCredentialsFD reads LOCAL_PEERCRED.
//
// Darwin's xucred carries uid and the group set but NOT the peer's pid, so a
// path selector is unavailable on this platform. That is stated rather than
// worked around: the selectors a darwin host can offer are uid and gid, an entry
// requiring unix:path will not match here, and an operator gets a refusal they
// can understand. Fabricating a pid to look feature-complete would resolve a
// path for the wrong process and match an entry the caller is not entitled to.
func peerCredentialsFD(fd uintptr) (PeerIdentity, error) {
	cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("workloadapi: read peer credentials: %w", err)
	}
	id := PeerIdentity{UID: int(cred.Uid)}
	if len(cred.Groups) > 0 {
		id.GID = int(cred.Groups[0])
	}
	return id, nil
}
