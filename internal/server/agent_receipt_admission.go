// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// beginPeerReceipt authenticates a terminal observation without admitting new
// customer work. The caller must check service admission after verifying the
// signature and route a restricted tenant exclusively to retained-attempt
// reconciliation. The shared lifetime still excludes concurrent erasure.
func (a *agentService) beginPeerReceipt(ctx context.Context) (context.Context, mtls.PeerCertInfo, func(), error) {
	return a.beginPeerOperation(ctx, func(work context.Context) (mtls.PeerCertInfo, error) {
		info, err := peerInfo(work)
		if err != nil {
			return mtls.PeerCertInfo{}, err
		}
		return a.checkedPeerIdentity(work, info)
	})
}
