// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
)

// handleIncidentMigrationRevoke is H3's exact predecessor gate. It runs on the
// dedicated fleet bulkhead and can be reached only from an H2 action whose
// aggregate is already in revoking_predecessor after signed live verification.
func (d *issuanceDispatcher) handleIncidentMigrationRevoke(ctx context.Context, m orchestrator.Message) error {
	if d == nil || d.store == nil || d.orch == nil {
		return errors.New("server: incident migration revocation is not configured")
	}
	var intent orchestrator.IncidentPredecessorRevocationIntent
	if err := json.Unmarshal(m.Payload, &intent); err != nil {
		return fmt.Errorf("server: decode incident predecessor revocation: %w", err)
	}
	external := strings.TrimSpace(intent.PredecessorExternalCAID)
	if strings.TrimSpace(intent.RunID) == "" || strings.TrimSpace(intent.WaveID) == "" ||
		strings.TrimSpace(intent.IdentityID) == "" || strings.TrimSpace(intent.PredecessorCertificateID) == "" ||
		strings.TrimSpace(intent.PredecessorFingerprint) == "" || (strings.TrimSpace(intent.PredecessorCAID) == "") == (external == "") {
		return errors.New("server: incident predecessor revocation has incomplete immutable identity")
	}
	row, err := d.store.GetMigrationRun(ctx, m.TenantID, intent.RunID)
	if err != nil {
		return err
	}
	member, found := migration.Member(row.Run, intent.WaveID, intent.IdentityID)
	if !found || (row.Run.Incident == nil && !row.Run.RevokePredecessors) || member.Binding.PredecessorCertificateID != intent.PredecessorCertificateID ||
		cleanFingerprint(member.Binding.PredecessorFingerprint) != cleanFingerprint(intent.PredecessorFingerprint) ||
		member.Binding.PredecessorCAID != intent.PredecessorCAID ||
		(external != "" && (row.Run.Incident != nil || member.Binding.PredecessorExternalCAID != external)) {
		return errors.New("server: incident predecessor revocation drifted from the immutable H2 member")
	}
	cert, err := d.store.GetCertificate(ctx, m.TenantID, intent.PredecessorCertificateID)
	if err != nil {
		return err
	}
	if cleanFingerprint(cert.Fingerprint) != cleanFingerprint(intent.PredecessorFingerprint) || strings.TrimSpace(cert.Serial) == "" {
		return errors.New("server: incident predecessor inventory no longer matches the immutable H2 member")
	}
	if cert.Status != "superseded" && cert.Status != "revoked" {
		return fmt.Errorf("server: incident predecessor %s is %q before verified revocation", cert.ID, cert.Status)
	}
	// The revocation reason is an RFC 5280 enum. The stable event ID and H2
	// member receipt bind the incident/run/certificate details for audit.
	reason := string(crypto.RevocationReasonKeyCompromise)
	if row.Run.Incident == nil && intent.Reason == string(crypto.RevocationReasonSuperseded) {
		// A planned switch (P3): the predecessor is retired, not compromised.
		reason = intent.Reason
	}
	reasonCode := crypto.CRLReasonCode(crypto.RevocationReason(reason))
	if external != "" {
		// P3-L2: the vendor that issued the predecessor revokes it. The
		// revocation is recorded, and the member's verdict given, only once
		// the vendor accepted it; a vendor whose integration cannot revoke
		// pauses the run with the reason instead of retrying forever, and any
		// other failure is retried through the outbox. The vendor publishes
		// its own CRL.
		if cert.IssuingExternalCAID != external {
			return errors.New("server: the predecessor's recorded external issuer drifted from the member binding")
		}
		err := d.revokeExternalCertificate(ctx, m.TenantID, external, cert, reason, m.IdempotencyKey)
		if errors.Is(err, errExternalRevocationUnsupported) {
			return d.pauseSwitchOnVendorRefusal(ctx, m.TenantID, intent, external, cert.Serial, err)
		}
		if err != nil {
			return err
		}
		if err := d.orch.RevokeCertificateForCAWithEventID(ctx, m.TenantID,
			orchestrator.MigrationEventID(m.TenantID, intent.RunID, "predecessor-revoked:"+m.IdempotencyKey),
			cert.Fingerprint, cert.Serial, "", reason, reasonCode); err != nil {
			return err
		}
	} else {
		if err := d.orch.RevokeCertificateForCAWithEventID(ctx, m.TenantID,
			orchestrator.MigrationEventID(m.TenantID, intent.RunID, "predecessor-revoked:"+m.IdempotencyKey),
			cert.Fingerprint, cert.Serial, intent.PredecessorCAID, reason, reasonCode); err != nil {
			return err
		}
		// The predecessor's issuing authority owns its CRL. Publish that exact
		// authority before acknowledging the revocation gate; a platform CRL
		// cannot carry an intermediate CA's serial. The worker retries this
		// publication after a crash using the same event ID and immutable
		// predecessor binding.
		if err := d.publishPredecessorCRL(ctx, m.TenantID, intent.PredecessorCAID); err != nil {
			return err
		}
	}
	updated, err := d.orch.UpdateMigrationRun(ctx, m.TenantID, intent.RunID,
		orchestrator.MigrationEventID(m.TenantID, intent.RunID, "revocation-receipt:"+m.IdempotencyKey),
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			bound, ok := migration.Member(current, intent.WaveID, intent.IdentityID)
			if !ok || bound.Binding.PredecessorCertificateID != intent.PredecessorCertificateID ||
				bound.Binding.PredecessorCAID != intent.PredecessorCAID || bound.Binding.PredecessorExternalCAID != external {
				return current, nil, errors.New("server: incident revocation receipt names no exact current member")
			}
			return migration.Observe(current, migration.Observation{
				WaveID: intent.WaveID, IdentityID: intent.IdentityID,
				Stage: migration.StageRevocation, Verdict: migration.VerdictVerified,
			})
		})
	if err != nil {
		return err
	}
	return syncIncidentMigrationState(ctx, d.store, d.orch, d.audit, m.TenantID, updated)
}

func (d *issuanceDispatcher) publishPredecessorCRL(ctx context.Context, tenantID, caID string) error {
	if caID == IssuingCAID() {
		if d.publishCRL == nil {
			return errors.New("server: predecessor platform CA CRL publication is unavailable")
		}
		return d.publishCRL(ctx, tenantID)
	}
	if d.publishAuthorityCRL == nil {
		return errors.New("server: predecessor managed CA CRL publication is unavailable")
	}
	return d.publishAuthorityCRL(ctx, tenantID, caID)
}

// pauseSwitchOnVendorRefusal pauses a planned switch whose predecessor's
// vendor cannot revoke it through its integration (P3-L2): retrying changes
// nothing, and the member's revocation stays unconfirmed. The operator revokes
// at the vendor and resumes, or rolls the wave back.
func (d *issuanceDispatcher) pauseSwitchOnVendorRefusal(ctx context.Context, tenantID string, intent orchestrator.IncidentPredecessorRevocationIntent, external, serial string, cause error) error {
	reason := fmt.Sprintf("the external CA %s cannot revoke predecessor %s (member %s) through its integration: %v",
		external, serial, intent.IdentityID, cause)
	_, err := d.orch.UpdateMigrationRun(ctx, tenantID, intent.RunID,
		orchestrator.MigrationEventID(tenantID, intent.RunID, "vendor-revocation-refused:"+intent.WaveID+":"+intent.IdentityID),
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			if current.Status != migration.RunRunning {
				return current, nil, nil
			}
			paused, err := migration.PauseRun(current, reason)
			return paused, nil, err
		})
	return err
}
