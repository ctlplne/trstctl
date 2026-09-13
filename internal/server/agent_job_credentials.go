// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
)

// RedeemJobCredential hands a claimed job's credential material to the agent
// that holds its lease — once per attempt, ever (epic A3).
//
// The order of operations is deliberate. The material is RESOLVED before the
// single-use gate is taken, so a resolution failure (custody unavailable, a
// reference that no longer exists) refuses the call WITHOUT burning the
// attempt's one redemption — the agent can retry when custody returns. Nothing
// resolved leaves this function unless the gate grants: a refusal wipes it all.
//
// Every refusal is the same coarse PermissionDenied on the wire. The reasons —
// replayed, lease not held, stale attempt — are classified AFTER the fact for
// the audit event only, so a caller probing this endpoint cannot map the claim
// table's state from refusal shapes.
func (a *agentService) RedeemJobCredential(ctx context.Context, req *transport.RedeemJobCredentialRequest) (*transport.RedeemJobCredentialResponse, error) {
	info, err := a.peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if a.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent job ledger is not configured")
	}
	if a.relayCredentials == nil {
		return nil, status.Error(codes.FailedPrecondition, "relay credential redemption is not configured")
	}
	if req == nil || req.JobID <= 0 || req.Attempt <= 0 {
		return nil, status.Error(codes.InvalidArgument, "job_id and attempt are required")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	now := time.Now().UTC()

	// Fail-fast precheck and data read. The atomic authorization is the
	// redemption statement below, which re-verifies holdership; this read just
	// avoids resolving material for a caller that plainly does not hold the
	// lease, and fetches the sealed payload for the one that does.
	job, held, err := a.store.GetAgentJobForRedemption(ctx, info.TenantID, agentID, req.JobID, now)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load job for redemption: %v", err)
	}
	if !held || job.ClaimAttempts != req.Attempt {
		return nil, a.refuseRedemption(ctx, info.TenantID, info.CommonName, agentID, req, now)
	}
	if job.Destination == "connector.deploy" || job.Destination == "connector.test" || job.Destination == agentJobKindEndpointRenew || job.Destination == orchestrator.DestinationConnectorRollback {
		// Legacy rows may predate the role column. Decode only public routing
		// metadata, and refuse host credentials before resolving any secrets.
		var route struct {
			Connector string          `json:"connector"`
			Config    json.RawMessage `json:"target_config"`
		}
		if json.Unmarshal(job.Payload, &route) == nil {
			if vantage, known := connector.ShippedTargetVantage(route.Connector); known && vantage == connector.VantageHostAgent {
				configuredID, configErr := connector.TargetHostAgentID(route.Config)
				if job.RequiredAgentID != agentID || !agentHasRole(info.Roles, "host") || configErr != nil || (configuredID != "" && configuredID != agentID) {
					return nil, status.Error(codes.FailedPrecondition, "host work requires an exact destination assignment; review and requeue this job")
				}
			}
		}
	}
	if job.Destination == orchestrator.DestinationConnectorRollback {
		if err := a.store.CheckConnectorRollbackPayload(ctx, info.TenantID, job.Payload); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "current rollback authorization was not granted")
		}
	}

	material, err := a.relayCredentials.resolveJobCredential(ctx, info.TenantID, job)
	if err != nil {
		// Resolution failed BEFORE the gate: the attempt's redemption is not
		// burned, and the agent may retry. Unavailable, not denied — the agent
		// backs off instead of failing the job.
		return nil, status.Errorf(codes.Unavailable, "credential material is not resolvable right now")
	}

	binding := redemptionBinding(info.TenantID, agentID, job.Destination, job.IdempotencyKey, req.JobID, req.Attempt)
	// Secret resolution may take long enough for the lease or authorization to
	// change. Grant against the same snapshot using the time after resolution.
	now = time.Now().UTC()
	redemption, granted, err := a.store.RedeemAgentJobCredential(ctx, info.TenantID, agentID, req.JobID, req.Attempt, job, binding, now)
	if err != nil {
		material.wipe()
		return nil, status.Errorf(codes.Internal, "record redemption: %v", err)
	}
	if !granted {
		material.wipe()
		return nil, a.refuseRedemption(ctx, info.TenantID, info.CommonName, agentID, req, now)
	}

	// The grant is durable before the material crosses the channel, so there is
	// no state in which an agent holds material the ledger does not show. The
	// event carries reference NAMES only — they are metadata the tenant already
	// sees in its target configuration — never values.
	a.recordAgentJobEvent(ctx, info.TenantID, "agent.job.credential.redeemed", map[string]any{
		"agent": info.CommonName, "job_id": req.JobID, "attempt": req.Attempt,
		"audit_ref": redemption.AuditRef, "ref_names": material.refNames,
	})
	// The response values are DEEP-copied out of the resolver's locked buffers,
	// and the buffers are wiped before this function returns: a deferred wipe
	// would run before the gRPC codec marshals the response, and a shallow copy
	// would share the buffers' backing arrays — either way the agent would
	// receive zeroes. The copies live on the ordinary heap only until the codec
	// encodes them onto the encrypted channel; that transient is the same cost
	// the served secrets API pays, and the locked-buffer custody contract
	// resumes on the agent side, which moves each value into a locked buffer on
	// decode.
	items := make([]transport.RedeemedSecret, 0, len(material.items))
	for _, item := range material.items {
		items = append(items, transport.RedeemedSecret{
			Name:  item.Name,
			Value: append(secret.JSONBytes(nil), item.Value...),
		})
	}
	material.wipe()
	return &transport.RedeemJobCredentialResponse{
		AuditRef:    redemption.AuditRef,
		ExpiresUnix: redemption.ExpiresAt.Unix(),
		Items:       items,
	}, nil
}

// refuseRedemption classifies a refusal for the audit log and returns the one
// coarse wire error every refusal shares.
func (a *agentService) refuseRedemption(ctx context.Context, tenantID, agentCN, agentID string, req *transport.RedeemJobCredentialRequest, now time.Time) error {
	reason, classifyErr := a.store.AgentJobRedemptionRefusalReason(ctx, tenantID, agentID, req.JobID, req.Attempt, now)
	if classifyErr != nil {
		reason = "redemption_refused"
	}
	a.metrics.observeRedemptionRefusal(reason)
	a.recordAgentJobEvent(ctx, tenantID, "agent.job.credential.redemption_refused", map[string]any{
		"agent": agentCN, "job_id": req.JobID, "attempt": req.Attempt, "reason": reason,
	})
	return status.Error(codes.PermissionDenied, "redemption is not available for this job attempt")
}

// redemptionBinding is the non-secret digest tying a redemption row to the
// exact work it authorized. Evidence, not a key: the row's primary key is what
// enforces single-use.
func redemptionBinding(tenantID, agentID, destination, idempotencyKey string, jobID int64, attempt int) []byte {
	return []byte(crypto.SHA256Hex([]byte(strings.Join([]string{
		"relay.credential.redeem",
		tenantID,
		agentID,
		strconv.FormatInt(jobID, 10),
		strconv.Itoa(attempt),
		destination,
		idempotencyKey,
	}, "\x00"))))
}
