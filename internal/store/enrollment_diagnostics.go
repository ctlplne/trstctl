// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EnrollmentDiagnosticRetentionLimit bounds the number of distinct diagnosis
// keys retained for one tenant. Repeats collapse into Count, so a retry storm
// cannot evict every other useful failure.
const EnrollmentDiagnosticRetentionLimit = 200

// enrollmentDiagnosticObservationDedupLimit retains enough recent event ids to
// suppress the normal inline-projection plus tail-replay duplicate without
// turning a retry storm into an unbounded PostgreSQL table. Snapshots capture
// this window; a full rebuild starts empty and deterministically replays once.
const enrollmentDiagnosticObservationDedupLimit = 10000

// EnrollmentDiagnostic is the tenant-scoped read projection of one collapsed
// enrollment failure class. SourceEventID and EventSequence bind the latest
// fields to immutable evidence and make a replayed/out-of-order projection a
// no-op rather than another observation.
type EnrollmentDiagnostic struct {
	TenantID      string
	Protocol      string
	Step          string
	Cause         string
	Summary       string
	Remediation   string
	Actionable    bool
	ObservedAt    time.Time
	Count         int64
	SourceEventID string
	EventSequence uint64
}

// ApplyEnrollmentDiagnosticObservedTx projects one immutable observation. The
// caller supplies the event transaction and tenant GUC. Both the collapse and
// retention queries bind tenant_id explicitly, in addition to FORCE RLS.
func (s *Store) ApplyEnrollmentDiagnosticObservedTx(ctx context.Context, tx pgx.Tx, diagnostic EnrollmentDiagnostic) error {
	if diagnostic.TenantID == "" {
		return fmt.Errorf("store: enrollment diagnostic tenant id is required (AN-1)")
	}
	if diagnostic.Protocol == "" || diagnostic.Step == "" || diagnostic.Cause == "" || diagnostic.Summary == "" {
		return fmt.Errorf("store: enrollment diagnostic protocol, step, cause, and summary are required")
	}
	if diagnostic.ObservedAt.IsZero() || diagnostic.SourceEventID == "" || diagnostic.EventSequence == 0 {
		return fmt.Errorf("store: enrollment diagnostic event identity, sequence, and observation time are required")
	}
	var inserted int
	err := tx.QueryRow(ctx,
		`INSERT INTO enrollment_diagnostic_observations
		    (tenant_id, source_event_id, event_sequence, protocol, step, cause, observed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id, source_event_id) DO NOTHING
		 RETURNING 1`, diagnostic.TenantID, diagnostic.SourceEventID,
		int64(diagnostic.EventSequence), diagnostic.Protocol, diagnostic.Step, diagnostic.Cause, diagnostic.ObservedAt.UTC()).Scan(&inserted) // #nosec G115 -- JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: remember enrollment diagnostic event: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO enrollment_diagnostics
		    (tenant_id, protocol, step, cause, summary, remediation, actionable,
		     observed_at, observation_count, source_event_id, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10)
		 ON CONFLICT (tenant_id, protocol, step, cause) DO UPDATE SET
		    summary = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.summary ELSE enrollment_diagnostics.summary END,
		    remediation = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.remediation ELSE enrollment_diagnostics.remediation END,
		    actionable = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.actionable ELSE enrollment_diagnostics.actionable END,
		    observed_at = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.observed_at ELSE enrollment_diagnostics.observed_at END,
		    observation_count = enrollment_diagnostics.observation_count + 1,
		    source_event_id = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.source_event_id ELSE enrollment_diagnostics.source_event_id END,
		    event_sequence = GREATEST(enrollment_diagnostics.event_sequence, EXCLUDED.event_sequence)
		 WHERE enrollment_diagnostics.tenant_id = EXCLUDED.tenant_id`,
		diagnostic.TenantID, diagnostic.Protocol, diagnostic.Step, diagnostic.Cause,
		diagnostic.Summary, diagnostic.Remediation, diagnostic.Actionable,
		diagnostic.ObservedAt.UTC(), diagnostic.SourceEventID, int64(diagnostic.EventSequence)); err != nil { // #nosec G115 -- JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190)
		return fmt.Errorf("store: project enrollment diagnostic: %w", err)
	}

	// Retain the newest distinct keys for THIS tenant only. The deterministic
	// tie-breakers make rebuilds and replicas choose the same boundary.
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollment_diagnostics
		 WHERE tenant_id = $1
		   AND (protocol, step, cause) IN (
		       SELECT protocol, step, cause
		         FROM enrollment_diagnostics
		        WHERE tenant_id = $1
		        ORDER BY observed_at DESC, event_sequence DESC, protocol, step, cause
		        OFFSET $2
		   )`, diagnostic.TenantID, EnrollmentDiagnosticRetentionLimit); err != nil {
		return fmt.Errorf("store: enforce enrollment diagnostic retention: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollment_diagnostic_observations AS observation
		 WHERE observation.tenant_id = $1
		   AND NOT EXISTS (
		       SELECT 1
		         FROM enrollment_diagnostics AS diagnostic
		        WHERE diagnostic.tenant_id = $1
		          AND diagnostic.tenant_id = observation.tenant_id
		          AND diagnostic.protocol = observation.protocol
		          AND diagnostic.step = observation.step
		          AND diagnostic.cause = observation.cause
		   )`, diagnostic.TenantID); err != nil {
		return fmt.Errorf("store: prune evicted enrollment diagnostic observations: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollment_diagnostic_observations
		 WHERE tenant_id = $1
		   AND source_event_id IN (
		       SELECT source_event_id
		         FROM enrollment_diagnostic_observations
		        WHERE tenant_id = $1
		        ORDER BY event_sequence DESC, source_event_id
		        OFFSET $2
		   )`, diagnostic.TenantID, enrollmentDiagnosticObservationDedupLimit); err != nil {
		return fmt.Errorf("store: bound enrollment diagnostic event deduplication: %w", err)
	}
	return nil
}

// ListEnrollmentDiagnostics returns only the authenticated tenant's recent
// diagnoses, newest first. The explicit predicate is load-bearing even with RLS:
// it is the repository contract and lets the AN-1 analyzer prove the boundary.
func (s *Store) ListEnrollmentDiagnostics(ctx context.Context, tenantID string, limit int) ([]EnrollmentDiagnostic, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: enrollment diagnostic tenant id is required (AN-1)")
	}
	if limit <= 0 || limit > EnrollmentDiagnosticRetentionLimit {
		limit = EnrollmentDiagnosticRetentionLimit
	}
	out := make([]EnrollmentDiagnostic, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, protocol, step, cause, summary, remediation,
			        actionable, observed_at, observation_count, source_event_id, event_sequence
			   FROM enrollment_diagnostics
			  WHERE tenant_id = $1
			  ORDER BY observed_at DESC, event_sequence DESC, protocol, step, cause
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var diagnostic EnrollmentDiagnostic
			var sequence int64
			if err := rows.Scan(&diagnostic.TenantID, &diagnostic.Protocol, &diagnostic.Step,
				&diagnostic.Cause, &diagnostic.Summary, &diagnostic.Remediation,
				&diagnostic.Actionable, &diagnostic.ObservedAt, &diagnostic.Count,
				&diagnostic.SourceEventID, &sequence); err != nil {
				return err
			}
			diagnostic.EventSequence = uint64(sequence) // #nosec G115 -- constrained positive bigint written from a JetStream sequence (CWE-190)
			out = append(out, diagnostic)
		}
		return rows.Err()
	})
	return out, err
}
