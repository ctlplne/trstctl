// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const EventCertificateFindingRenewed = "licensed_crypto.migration.certificate_finding_renewed"

// CertificateFindingRenewed joins an ordinary host renewal to the active PQC
// migration. The control plane accepts it only after signed listener readback,
// host custody, an exact rotation-run binding and an unbroken certificate
// replacement chain. The event advances CBOM and the rollback successor;
// the original pre-migration pin stays unchanged on the host.
type CertificateFindingRenewed struct {
	RunID                    string                        `json:"run_id"`
	AssetID                  string                        `json:"asset_id"`
	IdentityID               string                        `json:"identity_id"`
	TargetID                 string                        `json:"target_id"`
	TargetRevision           string                        `json:"target_revision"`
	PredecessorFingerprint   string                        `json:"predecessor_fingerprint"`
	CertificateFingerprint   string                        `json:"certificate_fingerprint"`
	Before                   projections.CBOMAssetObserved `json:"before"`
	After                    projections.CBOMAssetObserved `json:"after"`
	Transcript               transport.ProbeTranscript     `json:"transcript"`
	AgentID                  string                        `json:"agent_id"`
	JobID                    int64                         `json:"job_id"`
	Attempt                  int                           `json:"attempt"`
	EvidenceDigest           string                        `json:"evidence_digest"`
	ReceiptStatement         string                        `json:"receipt_statement"`
	ReceiptSignature         string                        `json:"receipt_signature"`
	ReceiptSignerFingerprint string                        `json:"receipt_signer_fingerprint"`
}

func (p *ProgressProjection) activeCertificateBinding(tenantID, identityID, targetID string) (CertificateFindingApplied, string, bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var matched CertificateFindingApplied
	var current string
	for key, ev := range p.certificateEvents {
		if key.tenantID != tenantID || p.items[key].Status != TLSFindingApplied {
			continue
		}
		var applied CertificateFindingApplied
		if err := json.Unmarshal(ev.Data, &applied); err != nil {
			return matched, "", false, err
		}
		if applied.IdentityID != identityID || applied.TargetID != targetID {
			continue
		}
		if matched.RunID != "" {
			return matched, "", false, errors.New("pqcmigration: multiple active certificate migrations bind the same identity and target")
		}
		matched, current = applied, p.items[key].CertificateFingerprint
	}
	return matched, current, matched.RunID != "", nil
}

func (p *ProgressProjection) currentCertificateFingerprint(tenantID, runID, assetID string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	item, found := p.items[progressKey{tenantID: tenantID, runID: runID, assetID: assetID}]
	return item.CertificateFingerprint, found && item.Status == TLSFindingApplied
}

// RecordCertificateRenewalResult is called for every verified ordinary host
// renewal. It is a no-op unless that identity and target have an active PQC
// migration; in that case missing or contradictory evidence fails the signed
// report rather than leaving the public CBOM behind the served certificate.
func (h HostAgentHooks) RecordCertificateRenewalResult(ctx context.Context, tenantID, agentID string, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, statement, signerFingerprint string) error {
	if claim.Destination != relay.KindEndpointRenew || req.Outcome != transport.JobOutcomeVerified {
		return nil
	}
	var intent relay.DeployIntent
	if err := json.Unmarshal(claim.Payload, &intent); err != nil {
		return err
	}
	if intent.PQCRunID != "" || intent.IdentityID == "" || intent.TargetID == "" || intent.PredecessorCertificateID == "" {
		return nil
	}
	applied, currentFingerprint, found, err := h.Progress.activeCertificateBinding(tenantID, intent.IdentityID, intent.TargetID)
	if err != nil || !found {
		return err
	}
	if h.Progress.hasCertificateRenewalReceipt(tenantID, applied.RunID, applied.AssetID,
		req.JobID, req.Attempt, req.CredentialFingerprint) {
		return nil
	}
	if intent.Connector != applied.Connector || intent.Revision != applied.TargetRevision ||
		agentID != applied.AgentID || intent.VerifyAddress != applied.After.Location ||
		intent.VerifyServerName != applied.Transcript.ServerName || intent.RotationRunID == "" ||
		req.CredentialFingerprint == "" || req.Custody == nil || statement == "" ||
		len(req.Signature) == 0 || signerFingerprint == "" {
		return errors.New("pqcmigration: host renewal differs from active migration binding or signed custody")
	}
	target, err := h.Store.GetDeploymentTarget(ctx, tenantID, intent.TargetID)
	if err != nil {
		return err
	}
	assigned, err := h.Store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config)
	if err != nil {
		return err
	}
	if !target.Enabled || target.RevisionID != intent.Revision || target.Type != intent.Connector || assigned != agentID {
		return errors.New("pqcmigration: host renewal target revision or agent changed")
	}
	rotation, err := h.Store.GetRotationRun(ctx, tenantID, intent.RotationRunID)
	if err != nil {
		return err
	}
	predecessor, err := h.Store.GetCertificate(ctx, tenantID, intent.PredecessorCertificateID)
	if err != nil {
		return err
	}
	if rotation.IdentityID != intent.IdentityID || !sameCertificateFingerprint(rotation.PredecessorFingerprint, predecessor.Fingerprint) {
		return errors.New("pqcmigration: host renewal differs from its rotation run")
	}
	cert, err := h.Store.GetCertificateByFingerprint(ctx, tenantID, req.CredentialFingerprint)
	if err != nil {
		return err
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		return err
	}
	if cert.ReplacesID == nil || *cert.ReplacesID != predecessor.ID || cert.KeyOrigin != string(custody.OriginHostAgent) ||
		info.KeyAlgorithm != TargetMLDSA65 || !sameCertificateFingerprint(info.SHA256Fingerprint, req.CredentialFingerprint) ||
		info.CommonName != intent.SubjectCommonName {
		return errors.New("pqcmigration: host renewal certificate is not the bound ML-DSA successor")
	}
	// A prior renewal may have completed before this receiver was installed.
	// The signed host rotation still provides an immutable replacement chain;
	// walk it back to the last PQC-projected leaf before advancing the CBOM.
	ancestor := predecessor
	linked := false
	for i := 0; i < 32; i++ {
		if sameCertificateFingerprint(ancestor.Fingerprint, currentFingerprint) {
			linked = true
			break
		}
		if ancestor.ReplacesID == nil || ancestor.KeyOrigin != string(custody.OriginHostAgent) {
			break
		}
		ancestor, err = h.Store.GetCertificate(ctx, tenantID, *ancestor.ReplacesID)
		if err != nil {
			return err
		}
	}
	if !linked {
		return errors.New("pqcmigration: renewed certificate is not descended from current PQC leaf")
	}
	var report relay.EndpointVerifyReport
	if err := strictHostPostureJSON([]byte(req.Detail), &report); err != nil || len(report.Results) != 1 {
		return errors.New("pqcmigration: signed renewal requires one listener transcript")
	}
	result, tr := report.Results[0], report.Results[0].Transcript
	if err := tr.Validate(); err != nil {
		return err
	}
	if result.EndpointID != intent.TargetID || tr.Address != intent.VerifyAddress || tr.ServerName != intent.VerifyServerName ||
		tr.Vantage != transport.VantageLocal || !tr.Reached || tr.Mismatch != certinfo.MismatchNone ||
		!sameCertificateFingerprint(tr.ExpectedFingerprint, req.CredentialFingerprint) ||
		!sameCertificateFingerprint(tr.ObservedFingerprint, req.CredentialFingerprint) || tr.Digest() != req.EvidenceDigest {
		return errors.New("pqcmigration: signed renewal readback does not prove the served leaf")
	}
	assets, err := h.Store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return err
	}
	var asset *store.CryptoAsset
	for i := range assets {
		if assets[i].ID == applied.AssetID {
			asset = &assets[i]
			break
		}
	}
	if asset == nil || asset.Kind != "certificate-key" || asset.Location != intent.VerifyAddress ||
		!sameCertificateFingerprint(asset.CertificateFingerprint, currentFingerprint) {
		return errors.New("pqcmigration: CBOM no longer names the current PQC lineage")
	}
	before := projections.CBOMAssetObserved{ID: asset.ID, Kind: asset.Kind, Location: asset.Location,
		CertificateFingerprint: asset.CertificateFingerprint, Algorithm: asset.Algorithm, KeyBits: asset.KeyBits,
		Protocol: asset.Protocol, Cipher: asset.Cipher, Library: asset.Library, Strength: asset.Strength,
		QuantumVulnerable: asset.QuantumVulnerable, OutOfPolicy: asset.OutOfPolicy, Reasons: append([]string(nil), asset.Reasons...)}
	after := before
	after.CertificateFingerprint = req.CredentialFingerprint
	after.Reasons = append(after.Reasons, "ML-DSA-65 renewal served and signed by host target "+intent.TargetID)
	return h.appendHostReceiptEvent(ctx, tenantID, applied.RunID,
		fmt.Sprintf("%s:renew:%d:%d", applied.AssetID, req.JobID, req.Attempt),
		EventCertificateFindingRenewed, CertificateFindingRenewed{
			RunID: applied.RunID, AssetID: applied.AssetID, IdentityID: intent.IdentityID,
			TargetID: intent.TargetID, TargetRevision: intent.Revision,
			PredecessorFingerprint: predecessor.Fingerprint, CertificateFingerprint: req.CredentialFingerprint,
			Before: before, After: after, Transcript: tr, AgentID: agentID, JobID: req.JobID, Attempt: req.Attempt,
			EvidenceDigest: req.EvidenceDigest, ReceiptStatement: statement,
			ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), ReceiptSignerFingerprint: signerFingerprint,
		})
}

func (p *ProgressProjection) applyCertificateRenewed(ctx context.Context, ev eventspec.Event, renewed CertificateFindingRenewed) error {
	p.certificateApplyMu.Lock()
	defer p.certificateApplyMu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: renewed.RunID, assetID: renewed.AssetID}
	if projected, err := p.certificateEventAlreadyProjected(key, ev); projected || err != nil {
		return err
	}
	if err := renewed.Transcript.Validate(); err != nil {
		return err
	}
	p.mu.RLock()
	item, found := p.items[key]
	p.mu.RUnlock()
	if !found || item.Status != TLSFindingApplied || renewed.RunID == "" || renewed.AssetID == "" ||
		renewed.IdentityID == "" || renewed.TargetID != item.TargetID || renewed.TargetRevision != item.TargetRevision ||
		renewed.AgentID == "" || renewed.ReceiptSignature == "" || renewed.ReceiptStatement == "" ||
		renewed.Before.ID != renewed.AssetID || renewed.After.ID != renewed.AssetID ||
		!sameCertificateFingerprint(renewed.Before.CertificateFingerprint, item.CertificateFingerprint) ||
		!sameCertificateFingerprint(renewed.After.CertificateFingerprint, renewed.CertificateFingerprint) ||
		renewed.After.Algorithm != TargetMLDSA65 || renewed.Transcript.Vantage != transport.VantageLocal ||
		!renewed.Transcript.Reached || renewed.Transcript.Mismatch != certinfo.MismatchNone ||
		renewed.Transcript.Digest() != renewed.EvidenceDigest ||
		!sameCertificateFingerprint(renewed.Transcript.ObservedFingerprint, renewed.CertificateFingerprint) {
		return errors.New("pqcmigration: renewed certificate event contradicts current signed state")
	}
	if p.store != nil {
		if err := p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
			return p.store.ApplyCryptoAssetMigratedTx(ctx, tx, store.CryptoAsset{
				ID: renewed.After.ID, TenantID: ev.TenantID, Kind: renewed.After.Kind,
				Location: renewed.After.Location, CertificateFingerprint: renewed.After.CertificateFingerprint,
				Algorithm: renewed.After.Algorithm, KeyBits: renewed.After.KeyBits,
				Protocol: renewed.After.Protocol, Cipher: renewed.After.Cipher, Library: renewed.After.Library,
				Strength: renewed.After.Strength, QuantumVulnerable: renewed.After.QuantumVulnerable,
				OutOfPolicy: renewed.After.OutOfPolicy, Reasons: renewed.After.Reasons,
			}, ev.Sequence, eventTime(ev))
		}); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.certificateRenewalEvents[key] = cloneReceiptEvent(ev)
	p.certificateStateEvents[key] = cloneReceiptEvent(ev)
	item = p.items[key]
	item.CertificateFingerprint = renewed.CertificateFingerprint
	item.CertificateReadback = &CertificateReadback{Transcript: renewed.Transcript, AgentID: renewed.AgentID,
		JobID: renewed.JobID, Attempt: renewed.Attempt, EvidenceDigest: renewed.EvidenceDigest,
		ReceiptStatement: renewed.ReceiptStatement, ReceiptSignature: renewed.ReceiptSignature,
		ReceiptSignerFingerprint: renewed.ReceiptSignerFingerprint}
	item.UpdatedAt = eventTime(ev)
	p.items[key] = item
	p.mu.Unlock()
	return nil
}

func (p *ProgressProjection) hasCertificateRenewalReceipt(tenantID, runID, assetID string, jobID int64, attempt int, fingerprint string) bool {
	p.mu.RLock()
	ev, found := p.certificateRenewalEvents[progressKey{tenantID: tenantID, runID: runID, assetID: assetID}]
	p.mu.RUnlock()
	if !found {
		return false
	}
	var prior CertificateFindingRenewed
	return json.Unmarshal(ev.Data, &prior) == nil && prior.JobID == jobID && prior.Attempt == attempt &&
		sameCertificateFingerprint(prior.CertificateFingerprint, fingerprint)
}

// CertificateRenewalFingerprint is the newest verified, event-projected leaf.
// The initial applied receipt still retains the exact pre-migration predecessor.
func (p *ProgressProjection) CertificateRenewalFingerprint(tenantID, runID, assetID string) (string, bool) {
	return p.currentCertificateFingerprint(tenantID, runID, assetID)
}
