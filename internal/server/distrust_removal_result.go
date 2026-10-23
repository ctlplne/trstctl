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
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// distrustRemovalJob reports whether a claimed job is a distrusted-root
// removal (eMudhra, Part 4) rather than a migration's trust step, and returns
// its intent.
func distrustRemovalJob(claim store.AgentJobResultClaim) (relay.TrustDistributionIntent, bool) {
	var intent relay.TrustDistributionIntent
	if claim.Destination != relay.KindTrustDistribute || json.Unmarshal(claim.Payload, &intent) != nil ||
		intent.Operation != relay.TrustRemoveDistrusted {
		return relay.TrustDistributionIntent{}, false
	}
	return intent, true
}

// distrustRemovalStatus maps the host's closed outcome to the receipt state
// and the operator-facing reason. The reason is the control plane's own
// wording; no host text reaches it.
func distrustRemovalStatus(report relay.DistrustRemovalReport) (string, string) {
	switch report.State {
	case relay.DistrustRemovalRemoved:
		return servedstatus.ConnectorTrustAnchorRemoved, "removed the distrusted root (" + report.DistrustEntry + ") from the host trust store"
	case relay.DistrustRemovalAbsent:
		return servedstatus.ConnectorTrustAnchorAbsent, "nothing exists at the trust-store path any more"
	case relay.DistrustRemovalBundle:
		return servedstatus.ConnectorTrustAnchorRemovalRefused, "the file holds more than one certificate; remove the root with the host's trust tool (update-ca-certificates, update-ca-trust or the platform equivalent)"
	case relay.DistrustRemovalDifferent:
		return servedstatus.ConnectorTrustAnchorRemovalRefused, "the file now holds another certificate than the finding named; nothing was removed"
	case relay.DistrustRemovalNotListed:
		return servedstatus.ConnectorTrustAnchorRemovalRefused, "the host agent's distrust list does not name this certificate; give the agent the operator distrust file with --distrust-file"
	case relay.DistrustRemovalRefused:
		return servedstatus.ConnectorTrustAnchorRemovalRefused, "the host profile does not allow this path: add its directory to allowed_roots, and the path must not be a symlink"
	default:
		return servedstatus.ConnectorTrustAnchorRemovalFailed, "the read, the removal or the readback failed on the host; the anchor may remain"
	}
}

// recordDistrustRemovalResult projects the host's signed account of a
// distrusted-root removal onto the receipt queued with it. A retry of the
// same report uses the same event ID and cannot change it. A migration's
// trust job is recorded by the migration receiver and passes through here.
func (a *agentService) recordDistrustRemovalResult(ctx context.Context, info mtls.PeerCertInfo,
	claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	intent, ok := distrustRemovalJob(claim)
	if !ok {
		return nil
	}
	if req.Outcome != transport.JobOutcomeExecuted {
		return errors.New("distrusted root removal needs a terminal executed report")
	}
	var result relay.DistrustRemovalReport
	if err := decodeStrictJSON([]byte(req.Detail), &result); err != nil {
		return err
	}
	if err := relay.ValidateDistrustRemovalReport(intent, result, req.EvidenceDigest); err != nil {
		return err
	}
	queued, err := a.queuedDistrustRemovalReceipt(ctx, info.TenantID, req.JobID, intent)
	if err != nil {
		return err
	}
	status, reason := distrustRemovalStatus(result)
	statement := jobReceiptStatement(info, req)
	detail, err := json.Marshal(struct {
		Report            relay.DistrustRemovalReport `json:"report"`
		EvidenceDigest    string                      `json:"evidence_digest"`
		ReceiptStatement  string                      `json:"receipt_statement"`
		ReceiptSignature  string                      `json:"receipt_signature_base64"`
		SignerFingerprint string                      `json:"signer_fingerprint"`
		Agent             string                      `json:"agent"`
	}{result, req.EvidenceDigest, string(statement.Canonical()),
		base64.StdEncoding.EncodeToString(req.Signature), info.FingerprintSHA256, info.CommonName})
	if err != nil {
		return err
	}
	return a.recordDistrustRemovalReceipt(ctx, info.TenantID, claim, req, queued, status, reason, string(detail))
}

// recordDistrustRemovalFailure makes an agent's signed refusal to run the
// removal visible on the queued receipt, without projecting agent free text.
func (a *agentService) recordDistrustRemovalFailure(ctx context.Context, info mtls.PeerCertInfo,
	claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	intent, ok := distrustRemovalJob(claim)
	if !ok {
		return nil
	}
	queued, err := a.queuedDistrustRemovalReceipt(ctx, info.TenantID, req.JobID, intent)
	if err != nil {
		return err
	}
	reason := "the host agent could not run the removal; inspect the signed job receipt and host profile"
	switch strings.TrimSpace(req.Detail) {
	case "trust removal intent is invalid":
		reason = "the host agent rejected the queued removal intent"
	case "trust removal evidence could not be encoded":
		reason = "the host agent could not encode its removal evidence"
	}
	detail, err := json.Marshal(struct {
		Reason            string `json:"reason"`
		JobID             int64  `json:"job_id"`
		Attempt           int    `json:"attempt"`
		ReceiptSignature  string `json:"receipt_signature_base64"`
		SignerFingerprint string `json:"signer_fingerprint"`
		Agent             string `json:"agent"`
	}{reason, req.JobID, req.Attempt, base64.StdEncoding.EncodeToString(req.Signature), info.FingerprintSHA256, info.CommonName})
	if err != nil {
		return err
	}
	return a.recordDistrustRemovalReceipt(ctx, info.TenantID, claim, req, queued,
		servedstatus.ConnectorTrustAnchorRemovalFailed, reason, string(detail))
}

func (a *agentService) queuedDistrustRemovalReceipt(ctx context.Context, tenantID string, jobID int64,
	intent relay.TrustDistributionIntent) (store.ConnectorDeliveryReceipt, error) {
	if a.orch == nil || a.store == nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("distrusted root removal receipt receiver is unavailable")
	}
	queued, err := a.store.GetConnectorDeliveryReceiptForOutbox(ctx, tenantID, jobID)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if queued.Destination != relay.KindTrustDistribute || queued.OutboxID == nil || *queued.OutboxID != jobID ||
		!strings.EqualFold(queued.Fingerprint, intent.AnchorFingerprint) {
		return store.ConnectorDeliveryReceipt{}, errors.New("distrusted root removal receipt does not match the signed host result")
	}
	return queued, nil
}

func (a *agentService) recordDistrustRemovalReceipt(ctx context.Context, tenantID string,
	claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest, queued store.ConnectorDeliveryReceipt,
	status, reason, detail string) error {
	_, err := a.orch.RecordConnectorDeliveryWithEventID(ctx, tenantID,
		evidenceID("distrust-removal-result", tenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		store.ConnectorDeliveryReceipt{
			ID: queued.ID, OutboxID: queued.OutboxID, Destination: queued.Destination,
			Connector: queued.Connector, Target: queued.Target, Fingerprint: queued.Fingerprint,
			Status: status, Attempts: req.Attempt, Reason: reason, Detail: detail,
			IdempotencyKey: queued.IdempotencyKey,
		})
	return err
}
