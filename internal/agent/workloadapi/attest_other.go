// SPDX-License-Identifier: MPL-2.0

//go:build !linux && !darwin

package workloadapi

import "net"

// peerCredentials refuses on platforms with no UDS peer-credential mechanism.
//
// Refusing is the point. A Workload API that cannot distinguish its callers
// would hand any local process every identity the host can reach, so a build
// that cannot attest must decline to serve rather than serve weakly.
func peerCredentials(*net.UnixConn) (PeerIdentity, error) {
	return PeerIdentity{}, ErrAttestationUnsupported
}
