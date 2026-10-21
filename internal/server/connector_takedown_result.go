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

// recordConnectorTakedownResult projects the relay's signed account of an
// appliance object removal onto the queued receipt (A43).
func (a *agentService) recordConnectorTakedownResult(ctx context.Context,
	info mtls.PeerCertInfo, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, result relay.TakedownReport) error {
	if a.orch == nil || a.store == nil {
		return errors.New("connector takedown receipt receiver is unavailable")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, info.TenantID, req.JobID)
	if err != nil {
		return err
	}
	if queued.Destination != orchestrator.DestinationConnectorTakedown || queued.OutboxID == nil ||
		*queued.OutboxID != req.JobID || !strings.EqualFold(queued.Fingerprint, result.Fingerprint) {
		return errors.New("connector takedown queued receipt does not match the signed relay result")
	}
	status := ""
	switch result.State {
	case relay.TakedownRemoved:
		status = servedstatus.ConnectorTakenDown
	case relay.TakedownBound:
		status = servedstatus.ConnectorTakedownBound
	case relay.TakedownNotInstalled:
		status = servedstatus.ConnectorTakedownAbsent
	default:
		return errors.New("connector takedown has an unknown result")
	}
	statement := jobReceiptStatement(info, req)
	evidence := struct {
		Report            relay.TakedownReport `json:"report"`
		EvidenceDigest    string               `json:"evidence_digest"`
		ReceiptStatement  string               `json:"receipt_statement"`
		ReceiptSignature  string               `json:"receipt_signature_base64"`
		SignerFingerprint string               `json:"signer_fingerprint"`
		Agent             string               `json:"agent"`
	}{result, req.EvidenceDigest, string(statement.Canonical()),
		base64.StdEncoding.EncodeToString(req.Signature), info.FingerprintSHA256, info.CommonName}
	detail, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	_, err = a.orch.RecordConnectorDeliveryWithEventID(ctx, info.TenantID,
		evidenceID("connector-takedown-result", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		store.ConnectorDeliveryReceipt{
			ID: queued.ID, OutboxID: queued.OutboxID, IdentityID: queued.IdentityID,
			Destination: queued.Destination, Connector: queued.Connector, Target: queued.Target,
			Fingerprint: queued.Fingerprint, Status: status, Attempts: req.Attempt,
			Reason: result.State, Detail: string(detail), IdempotencyKey: queued.IdempotencyKey,
		})
	return err
}

// recordConnectorTakedownFailure records a relay's signed refusal or at-target
// failure on the queued receipt, classifying contact from the closed reason
// set rather than from agent-supplied text.
func (a *agentService) recordConnectorTakedownFailure(ctx context.Context,
	info mtls.PeerCertInfo, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest) error {
	if a.orch == nil || a.store == nil {
		return errors.New("connector takedown receipt receiver is unavailable")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, info.TenantID, req.JobID)
	if err != nil {
		return err
	}
	if queued.Destination != orchestrator.DestinationConnectorTakedown || queued.OutboxID == nil || *queued.OutboxID != req.JobID {
		return errors.New("connector takedown queued receipt does not match the signed relay refusal")
	}
	reason := strings.TrimSpace(req.Detail)
	status := servedstatus.ConnectorTakedownRefused
	receiptReason := "takedown_refused"
	summary := "the relay declined before contacting the appliance"
	if transport.TakedownReasonContactedTarget(reason) {
		status = servedstatus.ConnectorTakedownFailed
		receiptReason = "takedown_failed"
		summary = "the relay reached the appliance and the removal did not succeed"
	}
	switch reason {
	case transport.TakedownRefusedBadPayload, transport.TakedownRefusedUnsupported, transport.TakedownRefusedNoFingerprint,
		transport.TakedownFailedAtTarget, transport.RollbackRefusedNotExecutable, transport.RollbackRefusedNoCredential,
		transport.RollbackRefusedNoLockedMemory, transport.RollbackRefusedCapability:
	default:
		reason = "unrecognized relay reason; inspect the signed job receipt"
	}
	detail, err := json.Marshal(struct {
		Reason            string `json:"reason"`
		Summary           string `json:"summary"`
		JobID             int64  `json:"job_id"`
		Attempt           int    `json:"attempt"`
		ReceiptSignature  string `json:"receipt_signature_base64"`
		SignerFingerprint string `json:"signer_fingerprint"`
		Agent             string `json:"agent"`
	}{reason, summary, req.JobID, req.Attempt, base64.StdEncoding.EncodeToString(req.Signature),
		info.FingerprintSHA256, info.CommonName})
	if err != nil {
		return err
	}
	_, err = a.orch.RecordConnectorDeliveryWithEventID(ctx, info.TenantID,
		evidenceID("connector-takedown-failure", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		store.ConnectorDeliveryReceipt{
			ID: queued.ID, OutboxID: queued.OutboxID, IdentityID: queued.IdentityID,
			Destination: queued.Destination, Connector: queued.Connector, Target: queued.Target,
			Fingerprint: queued.Fingerprint, Status: status, Attempts: req.Attempt,
			Reason: receiptReason, Detail: string(detail), IdempotencyKey: queued.IdempotencyKey,
		})
	return err
}
