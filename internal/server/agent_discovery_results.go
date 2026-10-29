// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/sshcollection"
	"trstctl.com/trstctl/internal/store"
)

// ingestDiscoveryJobReport routes the signed public readback for the three
// discovery executors; each receiver validates its own immutable command.
func (a *agentService) ingestDiscoveryJobReport(ctx context.Context, info mtls.PeerCertInfo, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	switch claim.Destination {
	case relay.KindDiscoveryRun:
		if a.recordDiscoveryScan == nil {
			return errors.New("discovery result receiver is not configured")
		}
		return a.recordDiscoveryScan(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)
	case sshcollection.Destination:
		if req.Outcome != transport.JobOutcomeExecuted {
			return errors.New("SSH collection requires a terminal executed readback report")
		}
		if a.recordSSHCollection == nil {
			return errors.New("SSH collection receiver is unavailable")
		}
		return a.recordSSHCollection(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail, req.EvidenceDigest)
	case relay.KindADCSInventory, relay.KindADCSNestedGroups, relay.KindADCSEndpointProbe:
		if a.recordADCSInventory == nil {
			return errors.New("AD CS inventory result receiver is not configured")
		}
		return a.recordADCSInventory(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)

	default:
		return errors.New("unknown discovery readback executor")
	}
}
