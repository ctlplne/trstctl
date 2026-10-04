// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/reportarchive"
)

// ComplianceReportRun is a read-model receipt for one immutable due edge. The
// archive reference points to exact signed bytes. EventSequence orders
// projection transitions on replay.
type ComplianceReportRun struct {
	ID              string
	TenantID        string
	ScheduleID      string
	DueAt           time.Time
	Framework       string
	ReportType      string
	Status          string
	RetryGeneration int
	Attempt         int
	NextAttemptAt   time.Time
	ErrorCode       string
	ArtifactRef     string
	ArtifactDigest  string
	CompletedAt     time.Time
	EventSequence   uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var complianceReportErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidateComplianceReportRun checks a proposed event projection before its
// source event is appended. Producers may use a placeholder positive sequence;
// the projector checks the actual source sequence again on apply.
func ValidateComplianceReportRun(run ComplianceReportRun) error {
	if _, err := uuid.Parse(run.ID); err != nil {
		return errors.New("store: report run id must be a UUID")
	}
	if _, err := uuid.Parse(run.TenantID); err != nil {
		return errors.New("store: report run tenant must be a UUID")
	}
	if _, err := uuid.Parse(run.ScheduleID); err != nil {
		return errors.New("store: report run schedule must be a UUID")
	}
	if run.DueAt.IsZero() || run.Framework == "" || run.ReportType == "" ||
		run.EventSequence == 0 || run.EventSequence > math.MaxInt64 ||
		run.RetryGeneration < 0 || run.Attempt < 0 || run.Attempt > 5 ||
		run.CreatedAt.IsZero() || run.UpdatedAt.IsZero() {
		return errors.New("store: report run identity, due edge, event sequence, or timestamps are incomplete")
	}
	switch run.Status {
	case "queued":
		if run.RetryGeneration != 0 || run.Attempt != 0 || !run.NextAttemptAt.IsZero() || run.ErrorCode != "" {
			return errors.New("store: queued report run has retry or error state")
		}
	case "retrying":
		if run.Attempt >= 5 || run.NextAttemptAt.IsZero() ||
			(run.Attempt == 0 && (run.RetryGeneration == 0 || run.ErrorCode != "")) ||
			(run.Attempt > 0 && !complianceReportErrorCode.MatchString(run.ErrorCode)) {
			return errors.New("store: retrying report run needs bounded attempt, retry time, and code")
		}
	case "failed":
		if run.Attempt == 0 || !run.NextAttemptAt.IsZero() ||
			!complianceReportErrorCode.MatchString(run.ErrorCode) {
			return errors.New("store: failed report run needs an attempt and code")
		}
	case "completed":
		wantRef, refErr := reportarchive.Reference(run.TenantID, run.ID, run.ArtifactDigest)
		if run.Attempt == 0 || run.CompletedAt.IsZero() || !run.NextAttemptAt.IsZero() || run.ErrorCode != "" ||
			refErr != nil || run.ArtifactRef != wantRef {
			return errors.New("store: completed report run needs exact retained artifact and digest")
		}
	default:
		return errors.New("store: unsupported report run status")
	}
	if run.Status != "completed" && (run.ArtifactRef != "" || run.ArtifactDigest != "" || !run.CompletedAt.IsZero()) {
		return errors.New("store: unfinished report run cannot carry an artifact")
	}
	return nil
}

// ApplyComplianceReportRunTx projects one event, enforcing immutable due-edge
// identity and increasing event sequence. A completed run advances the schedule
// only if that exact due edge is still enabled; a pause or later replacement
// cannot be undone by a delayed worker result.
func (s *Store) ApplyComplianceReportRunTx(ctx context.Context, tx pgx.Tx, run ComplianceReportRun) error {
	if err := ValidateComplianceReportRun(run); err != nil {
		return err
	}
	if err := lockUpsertArbiterTx(ctx, tx, "compliance_report_runs", run.TenantID, run.ID); err != nil {
		return err
	}
	var old ComplianceReportRun
	err := scanComplianceReportRun(tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, schedule_id::text, due_at, framework,
		        report_type, status, retry_generation, attempt, next_attempt_at, error_code, artifact_ref,
		        artifact_digest, completed_at, event_sequence, created_at, updated_at
		   FROM compliance_report_runs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		run.TenantID, run.ID), &old)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) && run.RetryGeneration != 0 {
		return errors.New("store: report run cannot begin in a requeue generation")
	}
	if err == nil {
		if old.ScheduleID != run.ScheduleID || !old.DueAt.Equal(run.DueAt) ||
			old.Framework != run.Framework || old.ReportType != run.ReportType ||
			!old.CreatedAt.Equal(run.CreatedAt) {
			return errors.New("store: report run identity conflicts with retained due edge")
		}
		if old.EventSequence == run.EventSequence {
			if old.Status == run.Status && old.RetryGeneration == run.RetryGeneration && old.Attempt == run.Attempt &&
				old.ErrorCode == run.ErrorCode && old.ArtifactDigest == run.ArtifactDigest &&
				old.ArtifactRef == run.ArtifactRef && old.CompletedAt.Equal(run.CompletedAt) &&
				old.NextAttemptAt.Equal(run.NextAttemptAt) && old.UpdatedAt.Equal(run.UpdatedAt) {
				return nil
			}
			return errors.New("store: report run event sequence conflicts with retained receipt")
		}
		requeued := old.Status == "failed" && run.Status == "retrying" &&
			run.RetryGeneration == old.RetryGeneration+1 && run.Attempt == 0
		if old.EventSequence > run.EventSequence || old.Status == "completed" ||
			(!requeued && (run.RetryGeneration != old.RetryGeneration || run.Attempt < old.Attempt)) ||
			(old.Status == "failed" && !requeued) {
			return errors.New("store: report run transition is stale or terminal")
		}
	}
	var nextAttempt, completed any
	if !run.NextAttemptAt.IsZero() {
		nextAttempt = run.NextAttemptAt
	}
	if !run.CompletedAt.IsZero() {
		completed = run.CompletedAt
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO compliance_report_runs
		        (tenant_id, id, schedule_id, due_at, framework, report_type, status,
		         retry_generation, attempt, next_attempt_at, error_code, artifact_ref, artifact_digest,
		         completed_at, event_sequence, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		 ON CONFLICT (tenant_id, id) DO UPDATE SET
		        status = EXCLUDED.status, retry_generation = EXCLUDED.retry_generation,
		        attempt = EXCLUDED.attempt,
		        next_attempt_at = EXCLUDED.next_attempt_at, error_code = EXCLUDED.error_code,
		        artifact_ref = EXCLUDED.artifact_ref, artifact_digest = EXCLUDED.artifact_digest,
		        completed_at = EXCLUDED.completed_at, event_sequence = EXCLUDED.event_sequence,
		        updated_at = EXCLUDED.updated_at`,
		run.TenantID, run.ID, run.ScheduleID, run.DueAt, run.Framework, run.ReportType,
		run.Status, run.RetryGeneration, run.Attempt, nextAttempt, run.ErrorCode, run.ArtifactRef,
		run.ArtifactDigest, completed, run.EventSequence, run.CreatedAt, run.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: project report run: %w", err)
	}
	if run.Status == "completed" {
		_, err = tx.Exec(ctx,
			`UPDATE compliance_report_schedules
			    SET next_run_at = GREATEST($4::timestamptz, $3::timestamptz)
			                      + make_interval(secs => interval_seconds),
			        updated_at = $4
			  WHERE tenant_id = $1 AND id = $2 AND enabled AND next_run_at = $3`,
			run.TenantID, run.ScheduleID, run.DueAt, run.CompletedAt)
	}
	return err
}

// GetComplianceReportRun returns one exact receipt. The archive read must verify
// its digest; a historical report is never silently regenerated.
func (s *Store) GetComplianceReportRun(ctx context.Context, tenantID, id string) (ComplianceReportRun, error) {
	var out ComplianceReportRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanComplianceReportRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, schedule_id::text, due_at, framework,
			        report_type, status, retry_generation, attempt, next_attempt_at, error_code, artifact_ref,
			        artifact_digest, completed_at, event_sequence, created_at, updated_at
			   FROM compliance_report_runs WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

// GetComplianceReportRunByDue finds the one exact due-edge receipt. Its unique
// key is independent of the producer's run ID, so a restarted worker can find
// an already recorded completion before attempting another signature.
func (s *Store) GetComplianceReportRunByDue(ctx context.Context, tenantID, scheduleID string, dueAt time.Time) (ComplianceReportRun, error) {
	var out ComplianceReportRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanComplianceReportRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, schedule_id::text, due_at, framework,
			        report_type, status, retry_generation, attempt, next_attempt_at, error_code, artifact_ref,
			        artifact_digest, completed_at, event_sequence, created_at, updated_at
			   FROM compliance_report_runs
			  WHERE tenant_id = $1 AND schedule_id = $2 AND due_at = $3`,
			tenantID, scheduleID, dueAt), &out)
	})
	return out, err
}

// ListComplianceReportRunsPage returns one schedule's receipts newest due edge
// first. DueAt is unique within a tenant/schedule, so it is a stable keyset
// cursor even when a retry changes the receipt's update time.
func (s *Store) ListComplianceReportRunsPage(ctx context.Context, tenantID, scheduleID string, before time.Time, limit int) ([]ComplianceReportRun, error) {
	if limit < 1 || limit > 101 {
		return nil, errors.New("store: report run page query limit must be 1-101")
	}
	var cutoff any
	if !before.IsZero() {
		cutoff = before
	}
	var out []ComplianceReportRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, schedule_id::text, due_at, framework,
			        report_type, status, retry_generation, attempt, next_attempt_at, error_code, artifact_ref,
			        artifact_digest, completed_at, event_sequence, created_at, updated_at
			   FROM compliance_report_runs
			  WHERE tenant_id = $1 AND schedule_id = $2
			    AND ($3::timestamptz IS NULL OR due_at < $3)
			  ORDER BY due_at DESC LIMIT $4`, tenantID, scheduleID, cutoff, limit)
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

func scanComplianceReportRun(row rowScanner, run *ComplianceReportRun) error {
	var nextAttempt, completed *time.Time
	var sequence int64
	if err := row.Scan(&run.ID, &run.TenantID, &run.ScheduleID, &run.DueAt,
		&run.Framework, &run.ReportType, &run.Status, &run.RetryGeneration, &run.Attempt, &nextAttempt,
		&run.ErrorCode, &run.ArtifactRef, &run.ArtifactDigest, &completed, &sequence,
		&run.CreatedAt, &run.UpdatedAt); err != nil {
		return err
	}
	if nextAttempt != nil {
		run.NextAttemptAt = *nextAttempt
	}
	if completed != nil {
		run.CompletedAt = *completed
	}
	if sequence <= 0 {
		return errors.New("store: invalid report run event sequence")
	}
	run.EventSequence = uint64(sequence) // #nosec G115 -- event sequence is a positive PostgreSQL bigint.
	return nil
}
