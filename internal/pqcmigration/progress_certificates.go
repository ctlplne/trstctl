// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

const (
	CertificateFindingIssued             = "issued"
	CertificateFindingRollbackUnverified = "rollback_unverified"
)

// applyCertificateStarted joins issuance work into the same per-run denominator
// as TLS posture work. It runs with p.mu held by applyStarted.
func (p *ProgressProjection) applyCertificateStarted(ev eventspec.Event, started projections.LicensedCryptoMigrationStarted) {
	for _, intent := range started.Reissues {
		key := progressKey{tenantID: ev.TenantID, runID: intent.RunID, assetID: intent.AssetID}
		item := p.items[key]
		item.RunID, item.AssetID, item.FindingKind = intent.RunID, intent.AssetID, "certificate-key"
		item.TargetAlgorithm = intent.TargetAlgorithm
		// A delayed start can fill in the operator's requested algorithm, but it
		// cannot replace the effective algorithm proven by a later signed apply
		// or exact rollback receipt.
		if item.Status == "" || item.Status == TLSFindingQueued {
			item.EffectiveAlgorithm = intent.EffectiveAlgorithm
		}
		if item.Status == "" {
			item.Status, item.UpdatedAt = TLSFindingQueued, eventTime(ev)
		}
		p.items[key] = item
	}
}

// The historical asset_completed event proves that an issuer returned a leaf.
// It carries no deployment receipt. Replaying it must not claim that the
// endpoint changed, or invent a TLS observation.
func (p *ProgressProjection) applyCertificateIssued(ev eventspec.Event, issued projections.LicensedCryptoMigrationAssetCompleted) error {
	p.certificateApplyMu.Lock()
	defer p.certificateApplyMu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: issued.RunID, assetID: issued.AssetID}
	if projected, err := p.certificateEventAlreadyProjected(key, ev); projected || err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	item := p.items[key]
	item.RunID, item.AssetID, item.FindingKind = issued.RunID, issued.AssetID, "certificate-key"
	item.TargetAlgorithm, item.EffectiveAlgorithm = issued.TargetAlgorithm, issued.EffectiveAlgorithm
	item.CertificateFingerprint = issued.CertificateFingerprint
	// A delayed duplicate issuance event cannot undo a later rollback fact.
	if item.Status == "" || item.Status == TLSFindingQueued || item.Status == CertificateFindingIssued {
		item.Status, item.UpdatedAt = CertificateFindingIssued, eventTime(ev)
	}
	p.items[key] = item
	p.certificateStateEvents[key] = cloneReceiptEvent(ev)
	return nil
}

// Historical rollback restores CBOM inventory only. Successful endpoint
// recovery requires its own authenticated receiver evidence in the F202 repair.
func (p *ProgressProjection) applyCertificateRollback(ev eventspec.Event, restored projections.LicensedCryptoMigrationRollbackCompleted) error {
	p.certificateApplyMu.Lock()
	defer p.certificateApplyMu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: restored.RunID, assetID: restored.AssetID}
	if projected, err := p.certificateEventAlreadyProjected(key, ev); projected || err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	item := p.items[key]
	item.RunID, item.AssetID, item.FindingKind = restored.RunID, restored.AssetID, "certificate-key"
	item.Status, item.UpdatedAt = CertificateFindingRollbackUnverified, eventTime(ev)
	p.items[key] = item
	p.certificateStateEvents[key] = cloneReceiptEvent(ev)
	return nil
}
