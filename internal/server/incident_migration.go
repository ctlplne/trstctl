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
	if strings.TrimSpace(intent.RunID) == "" || strings.TrimSpace(intent.WaveID) == "" ||
		strings.TrimSpace(intent.IdentityID) == "" || strings.TrimSpace(intent.PredecessorCertificateID) == "" ||
		strings.TrimSpace(intent.PredecessorFingerprint) == "" || strings.TrimSpace(intent.PredecessorCAID) == "" {
		return errors.New("server: incident predecessor revocation has incomplete immutable identity")
	}
	row, err := d.store.GetMigrationRun(ctx, m.TenantID, intent.RunID)
	if err != nil {
		return err
	}
	member, found := migration.Member(row.Run, intent.WaveID, intent.IdentityID)
	if !found || row.Run.Incident == nil || member.Binding.PredecessorCertificateID != intent.PredecessorCertificateID ||
		cleanFingerprint(member.Binding.PredecessorFingerprint) != cleanFingerprint(intent.PredecessorFingerprint) ||
		member.Binding.PredecessorCAID != intent.PredecessorCAID {
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
	reason := "incident migration " + intent.RunID + " revoked exact verified predecessor " + cert.ID
	reasonCode := crypto.CRLReasonCode(crypto.RevocationReasonKeyCompromise)
	if err := d.orch.RevokeCertificateForCAWithEventID(ctx, m.TenantID,
		orchestrator.MigrationEventID(m.TenantID, intent.RunID, "predecessor-revoked:"+m.IdempotencyKey),
		cert.Fingerprint, cert.Serial, intent.PredecessorCAID, reason, reasonCode); err != nil {
		return err
	}
	updated, err := d.orch.UpdateMigrationRun(ctx, m.TenantID, intent.RunID,
		orchestrator.MigrationEventID(m.TenantID, intent.RunID, "revocation-receipt:"+m.IdempotencyKey),
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			bound, ok := migration.Member(current, intent.WaveID, intent.IdentityID)
			if !ok || bound.Binding.PredecessorCertificateID != intent.PredecessorCertificateID ||
				bound.Binding.PredecessorCAID != intent.PredecessorCAID {
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
	// Republish the CRL. Recording certificate.revoked updates the read model,
	// but a relying party only learns about it from a freshly published CRL (or
	// an OCSP answer derived from the same projection). Without this the
	// scheduled sweep is the only thing that eventually republishes, so a
	// KEY-COMPROMISE revocation — the most urgent kind there is, and the reason
	// this path exists — stayed invisible to verifiers for up to a full CRL
	// period. Every other revocation path already publishes here.
	if err := d.publishTenantCRL(ctx, m.TenantID); err != nil {
		return err
	}
	return syncIncidentMigrationState(ctx, d.store, d.orch, d.audit, m.TenantID, updated)
}
