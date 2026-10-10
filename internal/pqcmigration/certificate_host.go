// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const EventCertificateFindingApplied = "licensed_crypto.migration.certificate_finding_applied"

// CertificateFindingApplied is a host-signed observation of the actual
// listener. The after image is fixed in this event, so a cold projection never
// has to infer the certificate result from a later inventory scan.
type CertificateFindingApplied struct {
	RunID                    string                        `json:"run_id"`
	AssetID                  string                        `json:"asset_id"`
	IdentityID               string                        `json:"identity_id"`
	TargetID                 string                        `json:"target_id"`
	TargetRevision           string                        `json:"target_revision"`
	Connector                string                        `json:"connector"`
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

// RecordCertificateResult runs after mTLS, lease, detached signature, target
// verification and host custody admission. The event is appended before the
// exact claim retires, so a failed projection leaves the signed result retryable.
func (h HostAgentHooks) RecordCertificateResult(ctx context.Context, tenantID, agentID string, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, statement, signerFingerprint string) error {
	if claim.Destination != relay.KindEndpointRenew {
		return errors.New("pqcmigration: certificate result has wrong job kind")
	}
	var intent relay.DeployIntent
	if err := json.Unmarshal(claim.Payload, &intent); err != nil {
		return err
	}
	if intent.PQCRunID == "" || intent.PQCAssetID == "" || intent.PQCPredecessorFingerprint == "" ||
		intent.IdentityID == "" || intent.TargetID == "" || intent.Revision == "" || intent.RequiredAgentID == "" {
		return errors.New("pqcmigration: certificate claim is incomplete")
	}
	if agentID != intent.RequiredAgentID {
		return errors.New("pqcmigration: certificate report came from a different host")
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
		return errors.New("pqcmigration: certificate target revision or host assignment changed")
	}
	if req.Outcome != transport.JobOutcomeVerified {
		return h.appendHostReceiptEvent(ctx, tenantID, intent.PQCRunID, intent.PQCAssetID+":issue",
			EventCertificateFindingFailed, CertificateFindingFailure{RunID: intent.PQCRunID, AssetID: intent.PQCAssetID, Operation: "issue"})
	}
	if req.CredentialFingerprint == "" || req.Custody == nil || statement == "" || len(req.Signature) == 0 || signerFingerprint == "" {
		return errors.New("pqcmigration: verified certificate result lacks signed custody evidence")
	}
	if prior, found, err := h.Progress.certificateAppliedReceipt(tenantID, intent.PQCRunID, intent.PQCAssetID); err != nil {
		return err
	} else if found {
		if prior.TargetID != intent.TargetID || prior.TargetRevision != intent.Revision ||
			prior.PredecessorFingerprint != intent.PQCPredecessorFingerprint ||
			prior.CertificateFingerprint != req.CredentialFingerprint || prior.AgentID != agentID {
			return errors.New("pqcmigration: repeated host certificate result conflicts with the durable applied effect")
		}
		return nil
	}
	cert, err := h.Store.GetCertificateByFingerprint(ctx, tenantID, req.CredentialFingerprint)
	if err != nil {
		return err
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		return err
	}
	if info.KeyAlgorithm != TargetMLDSA65 || info.CommonName != intent.SubjectCommonName ||
		!sameCertificateFingerprint(info.SHA256Fingerprint, req.CredentialFingerprint) ||
		cert.KeyOrigin != string(custody.OriginHostAgent) { // source must be this host's CSR path
		return errors.New("pqcmigration: issued certificate differs from the bound ML-DSA host CSR")
	}
	var report relay.EndpointVerifyReport
	if err := strictHostPostureJSON([]byte(req.Detail), &report); err != nil || len(report.Results) != 1 {
		return errors.New("pqcmigration: signed certificate report must contain one listener transcript")
	}
	result := report.Results[0]
	tr := result.Transcript
	if err := tr.Validate(); err != nil {
		return err
	}
	if result.EndpointID != intent.TargetID || tr.Address != intent.VerifyAddress || tr.ServerName != intent.VerifyServerName ||
		tr.Vantage != transport.VantageLocal || !tr.Reached || tr.Mismatch != certinfo.MismatchNone ||
		!sameCertificateFingerprint(tr.ExpectedFingerprint, req.CredentialFingerprint) ||
		!sameCertificateFingerprint(tr.ObservedFingerprint, req.CredentialFingerprint) || tr.Digest() != req.EvidenceDigest {
		return errors.New("pqcmigration: signed listener readback does not prove the issued leaf")
	}
	assets, err := h.Store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return err
	}
	var priorAsset *store.CryptoAsset
	for i := range assets {
		if assets[i].ID == intent.PQCAssetID {
			priorAsset = &assets[i]
			break
		}
	}
	if priorAsset == nil || priorAsset.Kind != "certificate-key" || priorAsset.Location != intent.VerifyAddress ||
		!sameCertificateFingerprint(priorAsset.CertificateFingerprint, intent.PQCPredecessorFingerprint) {
		return errors.New("pqcmigration: current CBOM asset no longer names the served predecessor")
	}
	after := projections.CBOMAssetObserved{ID: priorAsset.ID, Kind: priorAsset.Kind, Location: priorAsset.Location,
		CertificateFingerprint: req.CredentialFingerprint, Algorithm: TargetMLDSA65, KeyBits: 0,
		Protocol: priorAsset.Protocol, Cipher: priorAsset.Cipher, Library: priorAsset.Library,
		Strength: "strong", QuantumVulnerable: false, OutOfPolicy: false,
		Reasons: []string{"ML-DSA-65 leaf served and read back from host target " + intent.TargetID + " in run " + intent.PQCRunID}}
	before := projections.CBOMAssetObserved{ID: priorAsset.ID, Kind: priorAsset.Kind, Location: priorAsset.Location,
		CertificateFingerprint: priorAsset.CertificateFingerprint, Algorithm: priorAsset.Algorithm,
		KeyBits: priorAsset.KeyBits, Protocol: priorAsset.Protocol, Cipher: priorAsset.Cipher,
		Library: priorAsset.Library, Strength: priorAsset.Strength,
		QuantumVulnerable: priorAsset.QuantumVulnerable, OutOfPolicy: priorAsset.OutOfPolicy,
		Reasons: append([]string(nil), priorAsset.Reasons...)}
	return h.appendHostReceiptEvent(ctx, tenantID, intent.PQCRunID, intent.PQCAssetID,
		EventCertificateFindingApplied, CertificateFindingApplied{
			RunID: intent.PQCRunID, AssetID: intent.PQCAssetID, IdentityID: intent.IdentityID,
			TargetID: intent.TargetID, TargetRevision: intent.Revision, Connector: intent.Connector,
			PredecessorFingerprint: intent.PQCPredecessorFingerprint, CertificateFingerprint: req.CredentialFingerprint,
			Before: before, After: after, Transcript: tr, AgentID: agentID, JobID: req.JobID, Attempt: req.Attempt,
			EvidenceDigest: req.EvidenceDigest, ReceiptStatement: statement,
			ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), ReceiptSignerFingerprint: signerFingerprint,
		})
}

func (p *ProgressProjection) certificateAppliedReceipt(tenantID, runID, assetID string) (CertificateFindingApplied, bool, error) {
	p.mu.RLock()
	ev, found := p.certificateEvents[progressKey{tenantID: tenantID, runID: runID, assetID: assetID}]
	p.mu.RUnlock()
	if !found {
		return CertificateFindingApplied{}, false, nil
	}
	var completed CertificateFindingApplied
	if err := json.Unmarshal(ev.Data, &completed); err != nil {
		return completed, false, err
	}
	return completed, true, nil
}

func (p *ProgressProjection) applyCertificateApplied(ctx context.Context, ev eventspec.Event, completed CertificateFindingApplied) error {
	p.certificateApplyMu.Lock()
	defer p.certificateApplyMu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: completed.RunID, assetID: completed.AssetID}
	if projected, err := p.certificateEventAlreadyProjected(key, ev); projected || err != nil {
		return err
	}
	if err := completed.Transcript.Validate(); err != nil {
		return err
	}
	if completed.RunID == "" || completed.AssetID == "" || completed.TargetID == "" || completed.IdentityID == "" ||
		completed.AgentID == "" || completed.ReceiptSignature == "" || completed.ReceiptStatement == "" ||
		completed.After.ID != completed.AssetID || completed.After.Algorithm != TargetMLDSA65 ||
		completed.Before.ID != completed.AssetID || !sameCertificateFingerprint(completed.Before.CertificateFingerprint, completed.PredecessorFingerprint) ||
		completed.After.CertificateFingerprint != completed.CertificateFingerprint ||
		completed.Transcript.Vantage != transport.VantageLocal || !completed.Transcript.Reached || completed.Transcript.Mismatch != certinfo.MismatchNone ||
		completed.Transcript.Digest() != completed.EvidenceDigest ||
		!sameCertificateFingerprint(completed.Transcript.ObservedFingerprint, completed.CertificateFingerprint) {
		return fmt.Errorf("pqcmigration: host certificate applied event is incomplete or contradictory")
	}
	if p.store != nil {
		if err := p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
			return p.store.ApplyCryptoAssetMigratedTx(ctx, tx, store.CryptoAsset{
				ID: completed.After.ID, TenantID: ev.TenantID, Kind: completed.After.Kind,
				Location: completed.After.Location, CertificateFingerprint: completed.After.CertificateFingerprint,
				Algorithm: completed.After.Algorithm, KeyBits: completed.After.KeyBits,
				Protocol: completed.After.Protocol, Cipher: completed.After.Cipher, Library: completed.After.Library,
				Strength: completed.After.Strength, QuantumVulnerable: completed.After.QuantumVulnerable,
				OutOfPolicy: completed.After.OutOfPolicy, Reasons: completed.After.Reasons,
			}, ev.Sequence, eventTime(ev))
		}); err != nil {
			return err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.certificateEvents == nil {
		p.certificateEvents = map[progressKey]eventspec.Event{}
	}
	p.certificateEvents[key] = cloneReceiptEvent(ev)
	p.certificateStateEvents[key] = cloneReceiptEvent(ev)
	item := p.items[key]
	item.RunID, item.AssetID, item.FindingKind = completed.RunID, completed.AssetID, "certificate-key"
	item.TargetID, item.TargetRevision, item.Connector = completed.TargetID, completed.TargetRevision, completed.Connector
	item.CertificateFingerprint, item.EffectiveAlgorithm = completed.CertificateFingerprint, TargetMLDSA65
	item.CertificateReadback = &CertificateReadback{Transcript: completed.Transcript, AgentID: completed.AgentID,
		JobID: completed.JobID, Attempt: completed.Attempt, EvidenceDigest: completed.EvidenceDigest,
		ReceiptStatement: completed.ReceiptStatement, ReceiptSignature: completed.ReceiptSignature,
		ReceiptSignerFingerprint: completed.ReceiptSignerFingerprint}
	item.Status, item.UpdatedAt = TLSFindingApplied, eventTime(ev)
	p.items[key] = item
	return nil
}

type CertificateReadback struct {
	Transcript               transport.ProbeTranscript `json:"transcript"`
	AgentID                  string                    `json:"agent_id"`
	JobID                    int64                     `json:"job_id"`
	Attempt                  int                       `json:"attempt"`
	EvidenceDigest           string                    `json:"evidence_digest"`
	ReceiptStatement         string                    `json:"receipt_statement"`
	ReceiptSignature         string                    `json:"receipt_signature"`
	ReceiptSignerFingerprint string                    `json:"receipt_signer_fingerprint"`
}

func sameCertificateFingerprint(a, b string) bool {
	a = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(a), "sha256:"), ":", ""))
	b = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(b), "sha256:"), ":", ""))
	return len(a) == 64 && a == b
}
