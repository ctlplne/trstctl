// SPDX-License-Identifier: MPL-2.0

package signing

import "net"

// peerAuthListener restricts accepted UDS connections to a single uid (the
// control plane's), as defense in depth on top of the socket's filesystem
// permissions. When the peer uid cannot be determined, production serving fails
// closed; only an explicit local-development non-Linux override may accept the
// filesystem-permissions-only fallback (SIGNER-002 / WIRE-009).
type peerAuthListener struct {
	net.Listener
	allowedUID                   int
	allowUndeterminedDevNonLinux bool
	// peerUID resolves the connecting process's uid. It is a field (defaulting to
	// the platform peerUID) so the rejection path is unit-testable without a real
	// cross-uid socket (SIGNER-006: the rejection branch was previously untested,
	// so a regression breaking the uid comparison would pass CI silently).
	peerUID func(net.Conn) (int, bool)
}

func newPeerAuthListener(ln net.Listener, allowedUID int, allowUndeterminedDevNonLinux bool) net.Listener {
	return &peerAuthListener{
		Listener:                     ln,
		allowedUID:                   allowedUID,
		allowUndeterminedDevNonLinux: allowUndeterminedDevNonLinux,
		peerUID:                      peerUID,
	}
}

func (l *peerAuthListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, ok := l.peerUID(c)
		if ok && uid == l.allowedUID {
			return c, nil
		}
		if !ok && l.allowUndeterminedDevNonLinux {
			return c, nil
		}
		_ = c.Close() // reject a peer whose uid does not match
	}
}
