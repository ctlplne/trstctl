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

// recordEndpointContainmentResult projects the structured signed host account
// onto the same receipt returned when the operator queued the exact job. A
// retry of the same report uses the same event ID and cannot change its result.
func (a *agentService) recordEndpointContainmentResult(ctx context.Context,
	info mtls.PeerCertInfo, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, result relay.ContainmentReport) error {
	if a.orch == nil || a.store == nil {
		return errors.New("endpoint containment receipt receiver is unavailable")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, info.TenantID, req.JobID)
	if err != nil {
		return err
	}
	if queued.Destination != orchestrator.DestinationEndpointContainment || queued.OutboxID == nil ||
		*queued.OutboxID != req.JobID || queued.Fingerprint != result.ExpectedFingerprint {
		return errors.New("endpoint containment queued receipt does not match the signed host result")
	}
	status := ""
	switch result.State {
	case relay.ContainmentStopped:
		status = servedstatus.ConnectorContainmentStopped
	case relay.ContainmentDifferentLeaf:
		status = servedstatus.ConnectorContainmentDifferentLeaf
	case relay.ContainmentUnverified:
		status = servedstatus.ConnectorContainmentUnverified
	case relay.ContainmentFailed:
		status = servedstatus.ConnectorContainmentFailed
	default:
		return errors.New("endpoint containment has an unknown result")
	}
	statement := jobReceiptStatement(info, req)
	evidence := struct {
		Report            relay.ContainmentReport `json:"report"`
		EvidenceDigest    string                  `json:"evidence_digest"`
		ReceiptStatement  string                  `json:"receipt_statement"`
		ReceiptSignature  string                  `json:"receipt_signature_base64"`
		SignerFingerprint string                  `json:"signer_fingerprint"`
		Agent             string                  `json:"agent"`
	}{result, req.EvidenceDigest, string(statement.Canonical()),
		base64.StdEncoding.EncodeToString(req.Signature), info.FingerprintSHA256, info.CommonName}
	detail, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	receipt := store.ConnectorDeliveryReceipt{
		ID: queued.ID, OutboxID: queued.OutboxID, IdentityID: queued.IdentityID,
		Destination: queued.Destination, Connector: queued.Connector, Target: queued.Target,
		Fingerprint: queued.Fingerprint, Status: status, Attempts: req.Attempt,
		Reason: result.State, Detail: string(detail), IdempotencyKey: queued.IdempotencyKey,
	}
	eventID := evidenceID("endpoint-containment-result", info.TenantID,
		fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID)
	if status == servedstatus.ConnectorContainmentStopped {
		_, err = a.orch.RecordConnectorDeliveryWithEventID(ctx, info.TenantID, eventID, receipt)
	} else {
		// A signed, accepted report is not the same as a stopped listener.
		// Keep the critical alert in the same SQL transaction as the receipt.
		_, err = a.orch.RecordEndpointContainmentFailure(ctx, info.TenantID, eventID, receipt)
	}
	return err
}

// recordEndpointContainmentFailure makes an agent's signed refusal visible on
// the same exact receipt as the queued command. No agent-supplied free text is
// projected: even a compromised host must not write arbitrary strings into the
// durable delivery timeline.
func (a *agentService) recordEndpointContainmentFailure(ctx context.Context,
	info mtls.PeerCertInfo, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest) error {
	if a.orch == nil || a.store == nil {
		return errors.New("endpoint containment receipt receiver is unavailable")
	}
	var intent relay.ContainmentIntent
	if err := json.Unmarshal(claim.Payload, &intent); err != nil || intent.ExpectedFingerprint == "" {
		return errors.New("endpoint containment failure has no queued exact leaf")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, info.TenantID, req.JobID)
	if err != nil {
		return err
	}
	if queued.Destination != orchestrator.DestinationEndpointContainment || queued.OutboxID == nil ||
		*queued.OutboxID != req.JobID || !strings.EqualFold(queued.Fingerprint, intent.ExpectedFingerprint) ||
		queued.IdentityID == nil || *queued.IdentityID != intent.IdentityID {
		return errors.New("endpoint containment queued receipt does not match the signed host refusal")
	}
	// These are closed reasons emitted by the shipped agent. Unknown or future
	// detail remains a failure without copying untrusted text into the event log.
	reason := "host containment could not be verified; inspect the signed job receipt and host profile"
	switch strings.TrimSpace(req.Detail) {
	case "endpoint containment intent is invalid":
		reason = "host rejected the queued containment intent"
	case "host profile has no containment binding for this exact target":
		reason = "host profile has no containment binding for this exact target"
	case "host containment profile is unusable":
		reason = "host containment profile is unusable"
	case "host containment executor is unavailable":
		reason = "host containment executor is unavailable"
	case "host containment probe could not run":
		reason = "host containment probe could not run or confirm the listener state"
	case "host containment report could not be encoded":
		reason = "host containment report could not be encoded"
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
	_, err = a.orch.RecordEndpointContainmentFailure(ctx, info.TenantID,
		evidenceID("endpoint-containment-failure", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		store.ConnectorDeliveryReceipt{
			ID: queued.ID, OutboxID: queued.OutboxID, IdentityID: queued.IdentityID,
			Destination: queued.Destination, Connector: queued.Connector, Target: queued.Target,
			Fingerprint: queued.Fingerprint, Status: servedstatus.ConnectorContainmentFailed,
			Attempts: req.Attempt, Reason: "host action refused", Detail: string(detail),
			IdempotencyKey: queued.IdempotencyKey,
		})
	return err
}
