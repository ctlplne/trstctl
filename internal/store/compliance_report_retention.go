// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ComplianceReportRetention is a completed report run's legal hold and expiry
// (A206): a person holds a run's signed report, and the opt-in report
// retention removes an unheld report once it is older than the window.
type ComplianceReportRetention struct {
	LegalHoldReason string
	LegalHoldBy     string
	LegalHoldAt     *time.Time
	// ExpiryRequestedAt is when the retention queued the report's removal; a
	// hold clears it, so a released run is queued again.
	ExpiryRequestedAt *time.Time
	ArtifactExpiredAt *time.Time
	EventSequence     uint64
}

// Held reports whether the run is under legal hold.
func (r ComplianceReportRetention) Held() bool { return r.LegalHoldAt != nil }

// ErrComplianceReportRetentionState refuses a hold the run's state does not
// allow: holding a run that is not completed, already held or expired, or
// releasing one that is not held.
var ErrComplianceReportRetentionState = errors.New("store: the report run's retention state does not allow that")

// ApplyComplianceReportLegalHoldTx projects a legal hold being placed (held)
// or released. Placing a hold cancels a queued removal. A replay of the same
// or an earlier event changes nothing.
func (s *Store) ApplyComplianceReportLegalHoldTx(ctx context.Context, tx pgx.Tx, tenantID, runID string, held bool, reason, by string, at time.Time, sequence uint64) error {
	current, status, err := lockComplianceReportRetentionTx(ctx, tx, tenantID, runID)
	if err != nil {
		return err
	}
	if current.EventSequence >= sequence {
		return nil
	}
	switch {
	case held && (status != "completed" || current.ArtifactExpiredAt != nil || current.Held()):
		return ErrComplianceReportRetentionState
	case !held && !current.Held():
		return ErrComplianceReportRetentionState
	}
	if held {
		_, err = tx.Exec(ctx,
			`UPDATE compliance_report_runs
			    SET legal_hold_reason = $3, legal_hold_by = $4, legal_hold_at = $5,
			        artifact_expiry_requested_at = NULL, retention_event_sequence = $6
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, runID, reason, by, at, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE compliance_report_runs
		    SET legal_hold_reason = '', legal_hold_by = '', legal_hold_at = NULL, retention_event_sequence = $3
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, runID, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// ComplianceReportArtifactExpiryDestination is the outbox destination that
// removes a run's report under the report retention.
const ComplianceReportArtifactExpiryDestination = "compliance.report_artifact.expire"

// ApplyComplianceReportArtifactExpiryRequestedTx projects the retention
// queuing a run's removal: it marks the run and, in the same transaction,
// queues the outbox row that removes the report (AN-6). A run that is held,
// expired or already queued changes nothing, and neither does a replay.
func (s *Store) ApplyComplianceReportArtifactExpiryRequestedTx(ctx context.Context, tx pgx.Tx, tenantID, runID string, at time.Time, sequence uint64, payload []byte) error {
	current, status, err := lockComplianceReportRetentionTx(ctx, tx, tenantID, runID)
	if err != nil {
		return err
	}
	if current.EventSequence >= sequence || status != "completed" || current.Held() ||
		current.ExpiryRequestedAt != nil || current.ArtifactExpiredAt != nil {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE compliance_report_runs SET artifact_expiry_requested_at = $3, retention_event_sequence = $4
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, runID, at, int64(sequence)); err != nil { // #nosec G115 -- event sequences fit int64 (CWE-190)
		return err
	}
	// One row per request: a run released after a hold is queued again.
	key := "report-expiry:" + runID + ":" + strconv.FormatUint(sequence, 10)
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2)`,
		tenantID, key).Scan(&exists); err != nil || exists {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $2, $3, $4)`, tenantID, ComplianceReportArtifactExpiryDestination, payload, key)
	return err
}

// ApplyComplianceReportArtifactExpiredTx projects the retention's confirmed
// removal of a run's report.
func (s *Store) ApplyComplianceReportArtifactExpiredTx(ctx context.Context, tx pgx.Tx, tenantID, runID string, at time.Time, sequence uint64) error {
	current, status, err := lockComplianceReportRetentionTx(ctx, tx, tenantID, runID)
	if err != nil {
		return err
	}
	if current.EventSequence >= sequence || current.ArtifactExpiredAt != nil {
		return nil
	}
	if status != "completed" || current.Held() {
		return ErrComplianceReportRetentionState
	}
	_, err = tx.Exec(ctx,
		`UPDATE compliance_report_runs SET artifact_expired_at = $3, retention_event_sequence = $4
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, runID, at, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

func lockComplianceReportRetentionTx(ctx context.Context, tx pgx.Tx, tenantID, runID string) (ComplianceReportRetention, string, error) {
	var current ComplianceReportRetention
	var status string
	var seq int64
	err := tx.QueryRow(ctx,
		`SELECT status, legal_hold_reason, legal_hold_by, legal_hold_at, artifact_expiry_requested_at,
		        artifact_expired_at, retention_event_sequence
		   FROM compliance_report_runs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, runID).
		Scan(&status, &current.LegalHoldReason, &current.LegalHoldBy, &current.LegalHoldAt,
			&current.ExpiryRequestedAt, &current.ArtifactExpiredAt, &seq)
	current.EventSequence = uint64(seq) // #nosec G115 -- non-negative by constraint (CWE-190)
	return current, status, err
}

// ComplianceReportRunsPastRetention returns up to limit completed runs that
// finished before cutoff, are not held, have no removal queued and still have
// their report, oldest first.
func (s *Store) ComplianceReportRunsPastRetention(ctx context.Context, tenantID string, cutoff time.Time, limit int) ([]ComplianceReportRun, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("store: report retention query limit must be 1-100")
	}
	var out []ComplianceReportRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, schedule_id::text, due_at, framework,
			        report_type, status, retry_generation, attempt, next_attempt_at, error_code, artifact_ref,
			        artifact_digest, completed_at, event_sequence, created_at, updated_at, dispatch,
			        legal_hold_reason, legal_hold_by, legal_hold_at, artifact_expiry_requested_at,
			        artifact_expired_at, retention_event_sequence
			   FROM compliance_report_runs
			  WHERE tenant_id = $1 AND status = 'completed' AND completed_at < $2
			    AND legal_hold_at IS NULL AND artifact_expiry_requested_at IS NULL AND artifact_expired_at IS NULL
			  ORDER BY completed_at, id LIMIT $3`, tenantID, cutoff, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var run ComplianceReportRun
			if err := scanComplianceReportRun(rows, &run); err != nil {
				return err
			}
			out = append(out, run)
		}
		return rows.Err()
	})
	return out, err
}
