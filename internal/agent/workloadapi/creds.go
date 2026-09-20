// SPDX-License-Identifier: BUSL-1.1

package workloadapi

import (
	"context"
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
)

// Attesting at the handshake, because that is where the raw connection is.
//
// gRPC hands the accepted net.Conn to the transport credentials and nowhere
// else — by the time a handler runs, peer.Peer carries addresses, not the
// socket. A UDS peer has no meaningful address, so attestation has to happen
// here or not at all.
//
// This is also the right place on the merits: a connection that cannot be
// attested is refused before it can send a single RPC, rather than being served
// up to a handler that then has to remember to check.

// peerAuthInfo carries the attested caller through gRPC's AuthInfo channel.
type peerAuthInfo struct {
	credentials.CommonAuthInfo
	identity PeerIdentity
}

// AuthType names the mechanism for gRPC's benefit.
func (peerAuthInfo) AuthType() string { return "workloadapi-uds-peercred" }

// peerCredentials is the TransportCredentials that attests each connection.
//
// It performs no cryptographic handshake, and it does not need to: a UDS is
// host-local, the socket directory is owner-only, and the identity that matters
// is the kernel's record of who connected — not a certificate the caller could
// present. Adding TLS here would authenticate a key the workload has no way to
// have, which is the problem the Workload API exists to solve.
type udsPeerCredentials struct{}

func (udsPeerCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	id, err := AttestPeer(rawConn)
	if err != nil {
		// The connection is dropped rather than served unattested. A caller we
		// cannot identify must not reach a handler that issues identities.
		return nil, nil, err
	}
	return rawConn, peerAuthInfo{identity: id}, nil
}

func (udsPeerCredentials) ClientHandshake(_ context.Context, _ string, _ net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("workloadapi: these credentials are server-side only")
}

func (udsPeerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "workloadapi-uds-peercred"}
}

func (c udsPeerCredentials) Clone() credentials.TransportCredentials { return c }

func (udsPeerCredentials) OverrideServerName(string) error { return nil }
