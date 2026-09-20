// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// syncIncidentMigrationState mirrors one H2 transition into H3's operator
// evidence projection. H2 remains execution authority; this row cannot release
// estate work. A terminal state is not projected until its signed audit bundle
// has been produced, so "executed" always has offline-verifiable evidence.
func syncIncidentMigrationState(
	ctx context.Context,
	st *store.Store,
	orch *orchestrator.Orchestrator,
	auditSvc *audit.Service,
	tenantID string,
	row store.MigrationRun,
) error {
	if row.Run.Incident == nil {
		return nil
	}
	if st == nil || orch == nil {
		return errors.New("server: incident migration evidence projection is not configured")
	}
	incident, err := st.GetIncidentFleetReissuanceRun(ctx, tenantID, row.Run.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("server: incident H2 run has no plan-first H3 projection")
		}
		return err
	}
	incident.Status, incident.Phase = incidentMigrationStatus(row.Run)
	incident.HaltedReason = row.Run.HaltReason
	incident.NextBatchIndex = len(row.Run.Waves) + 1
	incident.Batches = make([]store.FleetReissuanceBatch, 0, len(row.Run.Waves))
	incident.ReplacementIdentityIDs = nil
	incident.RevokedIdentityIDs = nil
	incident.FailedTargets = nil
	for index, wave := range row.Run.Waves {
		batch := store.FleetReissuanceBatch{
			Index: index + 1, Status: incidentWaveStatus(wave), HealthGate: incidentWaveGate(wave),
		}
		if wave.Phase != migration.PhaseComplete && wave.Phase != migration.PhaseRolledBack && incident.NextBatchIndex == len(row.Run.Waves)+1 {
			incident.NextBatchIndex = index + 1
		}
		for _, member := range wave.Members {
			batch.IdentityIDs = append(batch.IdentityIDs, member.IdentityID)
			if member.Binding.SuccessorFingerprint != "" {
				if _, certErr := st.GetCertificateByFingerprint(ctx, tenantID, member.Binding.SuccessorFingerprint); certErr == nil {
					// A successor is a new certificate generation for the same NHI,
					// not a new identity row. Keep this API's identity-ID contract:
					// the fingerprint proves the replacement exists, while the
					// immutable member names the identity that was replaced.
					batch.ReplacementIdentityIDs = append(batch.ReplacementIdentityIDs, member.IdentityID)
					incident.ReplacementIdentityIDs = appendUniqueIncidentID(incident.ReplacementIdentityIDs, member.IdentityID)
				}
			}
			if predecessor, certErr := st.GetCertificate(ctx, tenantID, member.Binding.PredecessorCertificateID); certErr == nil && predecessor.Status == "revoked" {
				incident.RevokedIdentityIDs = appendUniqueIncidentID(incident.RevokedIdentityIDs, member.IdentityID)
			}
			if member.TrustVerdict == migration.VerdictFailed || member.SuccessorVerdict == migration.VerdictFailed ||
				member.RollbackSuccessorVerdict == migration.VerdictFailed || member.RollbackTrustVerdict == migration.VerdictFailed {
				incident.FailedTargets = appendUniqueIncidentID(incident.FailedTargets, member.IdentityID)
			}
		}
		incident.Batches = append(incident.Batches, batch)
	}
	incident.HealthGates = incidentMigrationHealthGates(row.Run)
	terminal := row.Run.Status == migration.RunComplete || row.Run.Status == migration.RunRolledBack
	if terminal && (incident.EvidenceBundleFormat != "jws" || strings.TrimSpace(incident.EvidenceBundle) == "") {
		if auditSvc == nil {
			return errors.New("server: terminal incident migration cannot seal evidence without the audit signer")
		}
		// The evidence artifact is the exact run-specific chain, not a UI page.
		// A hard record cap would silently sign a valid-looking prefix for a large
		// incident and omit later cohort/revocation receipts. Contains keeps the
		// export run-scoped; leaving Limit at zero deliberately includes every
		// matching retained event.
		bundle, exportErr := auditSvc.Export(ctx, audit.Query{TenantID: tenantID, Contains: row.Run.ID})
		if exportErr != nil {
			return fmt.Errorf("server: seal incident migration evidence: %w", exportErr)
		}
		incident.EvidenceBundleFormat = "jws"
		incident.EvidenceBundle = bundle
	}
	eventID := orchestrator.MigrationEventID(tenantID, row.Run.ID,
		fmt.Sprintf("incident-mirror:%d", row.LastEventSequence))
	_, err = orch.RecordIncidentFleetReissuanceWithEventID(ctx, tenantID, eventID, incident)
	return err
}

func incidentMigrationStatus(run migration.Run) (string, string) {
	phase := "planned"
	for _, wave := range run.Waves {
		if wave.Started && wave.Phase != migration.PhaseComplete && wave.Phase != migration.PhaseRolledBack {
			phase = wave.ID + ":" + string(wave.Phase)
			break
		}
		if wave.Phase == migration.PhaseComplete || wave.Phase == migration.PhaseRolledBack {
			phase = wave.ID + ":" + string(wave.Phase)
		}
	}
	switch run.Status {
	case migration.RunComplete:
		return "executed", "fleet_reissued_verified_and_predecessors_revoked"
	case migration.RunRolledBack:
		return "rolled_back", "failed_cohort_rolled_back"
	default:
		return string(run.Status), phase
	}
}

func incidentWaveStatus(wave migration.RunWave) string {
	switch wave.Phase {
	case migration.PhasePlanned:
		return servedstatus.FleetBatchPlanned
	case migration.PhaseComplete:
		return servedstatus.FleetBatchExecuted
	case migration.PhaseRolledBack:
		return servedstatus.FleetBatchFailed
	default:
		if strings.TrimSpace(wave.HaltReason) != "" {
			return servedstatus.FleetBatchFailed
		}
		return servedstatus.FleetBatchWaitingVerification
	}
}

func incidentWaveGate(wave migration.RunWave) string {
	for _, member := range wave.Members {
		if member.TrustVerdict == migration.VerdictFailed || member.SuccessorVerdict == migration.VerdictFailed ||
			member.RollbackSuccessorVerdict == migration.VerdictFailed || member.RollbackTrustVerdict == migration.VerdictFailed {
			return servedstatus.FleetGateFailed
		}
	}
	if wave.Phase == migration.PhaseComplete {
		return servedstatus.FleetGatePassed
	}
	return servedstatus.FleetGateNotEvaluated
}

func incidentMigrationHealthGates(run migration.Run) []store.FleetReissuanceHealthGate {
	trust, live, revoked := servedstatus.FleetGatePassed, servedstatus.FleetGatePassed, servedstatus.FleetGatePassed
	for _, wave := range run.Waves {
		for _, member := range wave.Members {
			trust = mergeIncidentGate(trust, member.TrustVerdict)
			live = mergeIncidentGate(live, member.SuccessorVerdict)
			revoked = mergeIncidentGate(revoked, member.RevocationVerdict)
		}
	}
	return []store.FleetReissuanceHealthGate{
		{Name: "signed_trust_distribution", Status: trust},
		{Name: "signed_live_serving", Status: live},
		{Name: "exact_predecessor_revocation", Status: revoked},
	}
}

func mergeIncidentGate(current string, verdict migration.Verdict) string {
	if current == servedstatus.FleetGateFailed || verdict == migration.VerdictFailed {
		return servedstatus.FleetGateFailed
	}
	if current == servedstatus.FleetGateNotEvaluated || verdict == "" {
		return servedstatus.FleetGateNotEvaluated
	}
	return servedstatus.FleetGatePassed
}

func appendUniqueIncidentID(ids []string, id string) []string {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}
