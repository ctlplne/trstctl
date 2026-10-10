// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const EventCertificateFindingRolledBack = "licensed_crypto.migration.certificate_finding_rolled_back"

type CertificateFindingRolledBack struct {
	RunID                    string                        `json:"run_id"`
	AssetID                  string                        `json:"asset_id"`
	TargetID                 string                        `json:"target_id"`
	TargetRevision           string                        `json:"target_revision"`
	PredecessorFingerprint   string                        `json:"predecessor_fingerprint"`
	SuccessorFingerprint     string                        `json:"successor_fingerprint"`
	Restored                 projections.CBOMAssetObserved `json:"restored"`
	Transcript               transport.ProbeTranscript     `json:"transcript"`
	AgentID                  string                        `json:"agent_id"`
	JobID                    int64                         `json:"job_id"`
	Attempt                  int                           `json:"attempt"`
	EvidenceDigest           string                        `json:"evidence_digest"`
	ReceiptStatement         string                        `json:"receipt_statement"`
	ReceiptSignature         string                        `json:"receipt_signature"`
	ReceiptSignerFingerprint string                        `json:"receipt_signer_fingerprint"`
}

// RollbackLifecycleCandidate is derived only from the immutable signed host
// rollback and its matching applied receipt. It lets boot recovery finish a
// lifecycle event if the control plane stopped between those two appends.
type RollbackLifecycleCandidate struct {
	TenantID               string
	IdentityID             string
	AssetID                string
	PredecessorFingerprint string
	EventSequence          uint64
}

func (p *ProgressProjection) RollbackLifecycleCandidates() []RollbackLifecycleCandidate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]RollbackLifecycleCandidate, 0, len(p.certificateRollbackEvents))
	for key, rolledEvent := range p.certificateRollbackEvents {
		appliedEvent, found := p.certificateEvents[key]
		if !found {
			continue
		}
		var rolled CertificateFindingRolledBack
		var applied CertificateFindingApplied
		if json.Unmarshal(rolledEvent.Data, &rolled) != nil || json.Unmarshal(appliedEvent.Data, &applied) != nil ||
			applied.IdentityID == "" || applied.RunID != rolled.RunID || applied.AssetID != rolled.AssetID ||
			!sameCertificateFingerprint(applied.PredecessorFingerprint, rolled.PredecessorFingerprint) {
			continue
		}
		result = append(result, RollbackLifecycleCandidate{TenantID: key.tenantID, IdentityID: applied.IdentityID,
			AssetID: key.assetID, PredecessorFingerprint: rolled.PredecessorFingerprint, EventSequence: rolledEvent.Sequence})
	}
	return result
}

func (h HostAgentHooks) RecordCertificateRollbackResult(ctx context.Context, tenantID, agentID string, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, statement, signerFingerprint string) error {
	if claim.Destination != "connector.rollback" {
		return errors.New("pqcmigration: certificate rollback has wrong job kind")
	}
	var intent relay.RollbackIntent
	if err := json.Unmarshal(claim.Payload, &intent); err != nil {
		return err
	}
	if intent.PQCRunID == "" || intent.PQCAssetID == "" || intent.TargetID == "" || intent.TargetRevision == "" ||
		intent.RequiredAgentID == "" || intent.PredecessorFingerprint == "" || intent.SuccessorFingerprint == "" {
		return errors.New("pqcmigration: certificate rollback claim is incomplete")
	}
	if agentID != intent.RequiredAgentID {
		return errors.New("pqcmigration: rollback report came from a different host")
	}
	target, err := h.Store.GetDeploymentTarget(ctx, tenantID, intent.TargetID)
	if err != nil {
		return err
	}
	assigned, err := h.Store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config)
	if err != nil {
		return err
	}
	if !target.Enabled || target.RevisionID != intent.TargetRevision || target.Type != intent.Connector || assigned != agentID {
		return errors.New("pqcmigration: rollback target revision or assignment changed")
	}
	if req.Outcome != transport.JobOutcomeVerified {
		return h.appendHostReceiptEvent(ctx, tenantID, intent.PQCRunID, intent.PQCAssetID+":rollback",
			EventCertificateFindingFailed, CertificateFindingFailure{RunID: intent.PQCRunID, AssetID: intent.PQCAssetID, Operation: "rollback"})
	}
	completed, found, err := h.Progress.certificateAppliedReceipt(tenantID, intent.PQCRunID, intent.PQCAssetID)
	if err != nil {
		return err
	}
	if !found || completed.IdentityID != intent.IdentityID || completed.TargetID != intent.TargetID ||
		completed.TargetRevision != intent.TargetRevision ||
		!sameCertificateFingerprint(completed.PredecessorFingerprint, intent.PredecessorFingerprint) {
		return errors.New("pqcmigration: rollback differs from the applied host certificate")
	}
	// A lost response can replay the exact signed result after the rollback event
	// has moved the CBOM back to its predecessor. Check that immutable receipt
	// before checking the now-obsolete successor projection.
	if prior, found, err := h.Progress.certificateRollbackReceipt(tenantID, intent.PQCRunID, intent.PQCAssetID); err != nil {
		return err
	} else if found {
		if prior.TargetID != intent.TargetID || !sameCertificateFingerprint(prior.PredecessorFingerprint, intent.PredecessorFingerprint) || prior.AgentID != agentID ||
			!sameCertificateFingerprint(prior.SuccessorFingerprint, intent.SuccessorFingerprint) {
			return errors.New("pqcmigration: repeated rollback conflicts with the durable restored effect")
		}
		return nil
	}
	currentFingerprint, projected := h.Progress.currentCertificateFingerprint(tenantID, intent.PQCRunID, intent.PQCAssetID)
	if !projected ||
		!sameCertificateFingerprint(currentFingerprint, intent.SuccessorFingerprint) {
		return errors.New("pqcmigration: rollback differs from the applied signed successor")
	}
	var report relay.EndpointVerifyReport
	if err := strictHostPostureJSON([]byte(req.Detail), &report); err != nil || len(report.Results) != 1 {
		return errors.New("pqcmigration: signed rollback requires one listener transcript")
	}
	result := report.Results[0]
	tr := result.Transcript
	if err := tr.Validate(); err != nil {
		return err
	}
	if result.EndpointID != intent.TargetID || tr.Address != intent.VerifyAddress || tr.ServerName != intent.VerifyServerName ||
		tr.Vantage != transport.VantageLocal || !tr.Reached || tr.Mismatch != certinfo.MismatchNone ||
		!sameCertificateFingerprint(tr.ExpectedFingerprint, intent.PredecessorFingerprint) ||
		!sameCertificateFingerprint(tr.ObservedFingerprint, intent.PredecessorFingerprint) ||
		tr.Digest() != req.EvidenceDigest || statement == "" || len(req.Signature) == 0 || signerFingerprint == "" {
		return errors.New("pqcmigration: signed rollback readback does not prove the exact predecessor")
	}
	assets, err := h.Store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return err
	}
	currentFound := false
	for _, asset := range assets {
		if asset.ID == intent.PQCAssetID {
			currentFound = sameCertificateFingerprint(asset.CertificateFingerprint, intent.SuccessorFingerprint)
			break
		}
	}
	if !currentFound {
		return errors.New("pqcmigration: current CBOM asset no longer names the applied successor")
	}
	return h.appendHostReceiptEvent(ctx, tenantID, intent.PQCRunID, intent.PQCAssetID,
		EventCertificateFindingRolledBack, CertificateFindingRolledBack{
			RunID: intent.PQCRunID, AssetID: intent.PQCAssetID, TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
			PredecessorFingerprint: intent.PredecessorFingerprint, SuccessorFingerprint: intent.SuccessorFingerprint,
			Restored: completed.Before, Transcript: tr, AgentID: agentID, JobID: req.JobID, Attempt: req.Attempt,
			EvidenceDigest: req.EvidenceDigest, ReceiptStatement: statement,
			ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), ReceiptSignerFingerprint: signerFingerprint,
		})
}

func (p *ProgressProjection) certificateRollbackReceipt(tenantID, runID, assetID string) (CertificateFindingRolledBack, bool, error) {
	p.mu.RLock()
	ev, found := p.certificateRollbackEvents[progressKey{tenantID: tenantID, runID: runID, assetID: assetID}]
	p.mu.RUnlock()
	if !found {
		return CertificateFindingRolledBack{}, false, nil
	}
	var completed CertificateFindingRolledBack
	if err := json.Unmarshal(ev.Data, &completed); err != nil {
		return completed, false, err
	}
	return completed, true, nil
}

func (p *ProgressProjection) applyCertificateRolledBack(ctx context.Context, ev eventspec.Event, completed CertificateFindingRolledBack) error {
	if err := completed.Transcript.Validate(); err != nil {
		return err
	}
	if completed.RunID == "" || completed.AssetID == "" || completed.TargetID == "" || completed.AgentID == "" ||
		completed.ReceiptStatement == "" || completed.ReceiptSignature == "" ||
		completed.Restored.ID != completed.AssetID ||
		!sameCertificateFingerprint(completed.Restored.CertificateFingerprint, completed.PredecessorFingerprint) ||
		!sameCertificateFingerprint(completed.Transcript.ObservedFingerprint, completed.PredecessorFingerprint) ||
		completed.Transcript.Vantage != transport.VantageLocal || !completed.Transcript.Reached || completed.Transcript.Mismatch != certinfo.MismatchNone ||
		completed.Transcript.Digest() != completed.EvidenceDigest {
		return errors.New("pqcmigration: host certificate rollback event is incomplete or contradictory")
	}
	if p.store != nil {
		if err := p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
			return p.store.ApplyCryptoAssetRolledBackTx(ctx, tx, store.CryptoAsset{
				ID: completed.Restored.ID, TenantID: ev.TenantID, Kind: completed.Restored.Kind,
				Location: completed.Restored.Location, CertificateFingerprint: completed.Restored.CertificateFingerprint,
				Algorithm: completed.Restored.Algorithm, KeyBits: completed.Restored.KeyBits,
				Protocol: completed.Restored.Protocol, Cipher: completed.Restored.Cipher, Library: completed.Restored.Library,
				Strength: completed.Restored.Strength, QuantumVulnerable: completed.Restored.QuantumVulnerable,
				OutOfPolicy: completed.Restored.OutOfPolicy, Reasons: completed.Restored.Reasons,
			}, ev.Sequence, eventTime(ev))
		}); err != nil {
			return err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.certificateRollbackEvents == nil {
		p.certificateRollbackEvents = map[progressKey]eventspec.Event{}
	}
	key := progressKey{tenantID: ev.TenantID, runID: completed.RunID, assetID: completed.AssetID}
	p.certificateRollbackEvents[key] = cloneReceiptEvent(ev)
	item := p.items[key]
	item.RunID, item.AssetID, item.FindingKind = completed.RunID, completed.AssetID, "certificate-key"
	item.TargetID, item.TargetRevision = completed.TargetID, completed.TargetRevision
	item.CertificateFingerprint = completed.PredecessorFingerprint
	item.EffectiveAlgorithm = completed.Restored.Algorithm
	item.CertificateReadback = &CertificateReadback{Transcript: completed.Transcript, AgentID: completed.AgentID,
		JobID: completed.JobID, Attempt: completed.Attempt, EvidenceDigest: completed.EvidenceDigest,
		ReceiptStatement: completed.ReceiptStatement, ReceiptSignature: completed.ReceiptSignature,
		ReceiptSignerFingerprint: completed.ReceiptSignerFingerprint}
	item.Status, item.UpdatedAt = TLSFindingRolledBack, eventTime(ev)
	p.items[key] = item
	return nil
}
