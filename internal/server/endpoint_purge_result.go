// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// recordEndpointPurgeResult projects the structured signed host account of a
// material removal onto the receipt the operator got when queueing it (A49).
// A retry of the same report uses the same event ID and cannot change it.
func (a *agentService) recordEndpointPurgeResult(ctx context.Context,
	info mtls.PeerCertInfo, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, result relay.PurgeReport) error {
	if a.orch == nil || a.store == nil {
		return errors.New("endpoint purge receipt receiver is unavailable")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, info.TenantID, req.JobID)
	if err != nil {
		return err
	}
	if queued.Destination != orchestrator.DestinationEndpointPurge || queued.OutboxID == nil ||
		*queued.OutboxID != req.JobID || !strings.EqualFold(queued.Fingerprint, result.ExpectedFingerprint) {
		return errors.New("endpoint purge queued receipt does not match the signed host result")
	}
	status := ""
	switch result.State {
	case relay.PurgeRemoved:
		status = servedstatus.ConnectorPurged
	case relay.PurgeDifferentLeaf:
		status = servedstatus.ConnectorPurgeDifferentLeaf
	case relay.PurgeAbsent:
		status = servedstatus.ConnectorPurgeAbsent
	case relay.PurgeFailed:
		status = servedstatus.ConnectorPurgeFailed
	default:
		return errors.New("endpoint purge has an unknown result")
	}
	statement := jobReceiptStatement(info, req)
	evidence := struct {
		Report            relay.PurgeReport `json:"report"`
		EvidenceDigest    string            `json:"evidence_digest"`
		ReceiptStatement  string            `json:"receipt_statement"`
		ReceiptSignature  string            `json:"receipt_signature_base64"`
		SignerFingerprint string            `json:"signer_fingerprint"`
		Agent             string            `json:"agent"`
	}{result, req.EvidenceDigest, string(statement.Canonical()),
		base64.StdEncoding.EncodeToString(req.Signature), info.FingerprintSHA256, info.CommonName}
	detail, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	_, err = a.orch.RecordConnectorDeliveryWithEventID(ctx, info.TenantID,
		evidenceID("endpoint-purge-result", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		store.ConnectorDeliveryReceipt{
			ID: queued.ID, OutboxID: queued.OutboxID, IdentityID: queued.IdentityID,
			Destination: queued.Destination, Connector: queued.Connector, Target: queued.Target,
			Fingerprint: queued.Fingerprint, Status: status, Attempts: req.Attempt,
			Reason: result.State, Detail: string(detail), IdempotencyKey: queued.IdempotencyKey,
		})
	if err != nil || status != servedstatus.ConnectorPurged || queued.IdentityID == nil {
		return err
	}
	return a.closeDeployedStateAfterPurge(ctx, info.TenantID, *queued.IdentityID, queued.Fingerprint)
}

// closeDeployedStateAfterPurge moves an identity from deployed back to issued
// once no target still serves the purged leaf (B5-3). The purged receipt
// already drops the target from installed_on; this keeps the lifecycle
// state honest for an identity whose material is served nowhere. An identity
// still served by another target keeps its state.
func (a *agentService) closeDeployedStateAfterPurge(ctx context.Context, tenantID, identityID, fingerprint string) error {
	stillServed, err := a.store.DeliveredTargetsForFingerprint(ctx, tenantID, fingerprint)
	if err != nil || len(stillServed) > 0 {
		return err
	}
	ident, err := a.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil || ident.Status != string(orchestrator.StateDeployed) {
		return err
	}
	if err := a.orch.TransitionAfterVerifiedPurge(ctx, tenantID, identityID); err != nil && !errors.Is(err, orchestrator.ErrInvalidTransition) {
		return err
	}
	return nil
}

// recordEndpointPurgeFailure makes an agent's signed refusal visible on the
// queued receipt without projecting agent-supplied free text.
func (a *agentService) recordEndpointPurgeFailure(ctx context.Context,
	info mtls.PeerCertInfo, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest) error {
	if a.orch == nil || a.store == nil {
		return errors.New("endpoint purge receipt receiver is unavailable")
	}
	var intent relay.PurgeIntent
	if err := json.Unmarshal(claim.Payload, &intent); err != nil || intent.ExpectedFingerprint == "" {
		return errors.New("endpoint purge failure has no queued exact leaf")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, info.TenantID, req.JobID)
	if err != nil {
		return err
	}
	if queued.Destination != orchestrator.DestinationEndpointPurge || queued.OutboxID == nil ||
		*queued.OutboxID != req.JobID || !strings.EqualFold(queued.Fingerprint, intent.ExpectedFingerprint) ||
		queued.IdentityID == nil || *queued.IdentityID != intent.IdentityID {
		return errors.New("endpoint purge queued receipt does not match the signed host refusal")
	}
	reason := "host material removal could not run; inspect the signed job receipt and host profile"
	switch strings.TrimSpace(req.Detail) {
	case "endpoint purge intent is invalid":
		reason = "host rejected the queued purge intent"
	case "host rollback ledger is unavailable for purge":
		reason = "host rollback ledger is unavailable on the agent (start it with --host-rollback-dir)"
	case "host purge profile is unusable":
		reason = "host purge profile is unusable"
	case "host purge executor is unavailable":
		reason = "host purge executor is unavailable"
	case "host purge report could not be encoded":
		reason = "host purge report could not be encoded"
	}
	detail, err := json.Marshal(struct {
		Reason            string `json:"reason"`
		JobID             int64  `json:"job_id"`
		Attempt           int    `json:"attempt"`
		ReceiptSignature  string `json:"receipt_signature_base64"`
		SignerFingerprint string `json:"signer_fingerprint"`
		Agent             string `json:"agent"`
	}{reason, req.JobID, req.Attempt, base64.StdEncoding.EncodeToString(req.Signature),
		info.FingerprintSHA256, info.CommonName})
	if err != nil {
		return err
	}
	_, err = a.orch.RecordConnectorDeliveryWithEventID(ctx, info.TenantID,
		evidenceID("endpoint-purge-failure", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		store.ConnectorDeliveryReceipt{
			ID: queued.ID, OutboxID: queued.OutboxID, IdentityID: queued.IdentityID,
			Destination: queued.Destination, Connector: queued.Connector, Target: queued.Target,
			Fingerprint: queued.Fingerprint, Status: servedstatus.ConnectorPurgeFailed,
			Attempts: req.Attempt, Reason: "host action refused", Detail: string(detail),
			IdempotencyKey: queued.IdempotencyKey,
		})
	return err
}
