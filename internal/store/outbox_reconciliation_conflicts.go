// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutboxReconciliationConflict is the tenant-visible projection of one event
// whose receiver command was refused because its idempotency key already belongs
// to a different immutable outbox row. It stores hashes and source references,
// not a second executable copy of either command.
type OutboxReconciliationConflict struct {
	ID                         string
	TenantID                   string
	SourceEventID              string
	SourceEventSequence        uint64
	SourceEventType            string
	IdempotencyKey             string
	ExistingOutboxID           int64
	ExistingDestination        string
	ExistingEffectLane         string
	ExistingPayloadSHA256      string
	ExistingRequiredAgentRole  string
	ExistingRequiredAgentID    string
	CandidateDestination       string
	CandidateEffectLane        string
	CandidatePayloadSHA256     string
	CandidateRequiredAgentRole string
	CandidateRequiredAgentID   string
	Reason                     string
	Status                     string
	DetectedAt                 time.Time
}

// ApplyOutboxReconciliationConflictRecordedTx projects the immutable recovery
// incident. Replaying the exact source event is a no-op; a changed event with the
// same tenant/source identity is rejected instead of rewriting recovery evidence.
func (s *Store) ApplyOutboxReconciliationConflictRecordedTx(ctx context.Context, tx pgx.Tx, c OutboxReconciliationConflict) error {
	tag, err := tx.Exec(ctx,
		`INSERT INTO outbox_reconciliation_conflicts
		 (id, tenant_id, source_event_id, source_event_sequence, source_event_type,
		  idempotency_key, existing_outbox_id, existing_destination,
		  existing_effect_lane, existing_payload_sha256, existing_required_agent_role,
		  existing_required_agent_id,
		  candidate_destination, candidate_effect_lane, candidate_payload_sha256,
		  candidate_required_agent_role, candidate_required_agent_id, reason, status, detected_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		 ON CONFLICT (tenant_id, source_event_id) DO UPDATE
		 SET source_event_id = EXCLUDED.source_event_id
		 WHERE outbox_reconciliation_conflicts.id = EXCLUDED.id
		   AND outbox_reconciliation_conflicts.source_event_sequence = EXCLUDED.source_event_sequence
		   AND outbox_reconciliation_conflicts.source_event_type = EXCLUDED.source_event_type
		   AND outbox_reconciliation_conflicts.idempotency_key = EXCLUDED.idempotency_key
		   AND outbox_reconciliation_conflicts.existing_outbox_id = EXCLUDED.existing_outbox_id
		   AND outbox_reconciliation_conflicts.existing_destination = EXCLUDED.existing_destination
		   AND outbox_reconciliation_conflicts.existing_effect_lane = EXCLUDED.existing_effect_lane
		   AND outbox_reconciliation_conflicts.existing_payload_sha256 = EXCLUDED.existing_payload_sha256
		   AND outbox_reconciliation_conflicts.existing_required_agent_role = EXCLUDED.existing_required_agent_role
		   AND outbox_reconciliation_conflicts.existing_required_agent_id = EXCLUDED.existing_required_agent_id
		   AND outbox_reconciliation_conflicts.candidate_destination = EXCLUDED.candidate_destination
		   AND outbox_reconciliation_conflicts.candidate_effect_lane = EXCLUDED.candidate_effect_lane
		   AND outbox_reconciliation_conflicts.candidate_payload_sha256 = EXCLUDED.candidate_payload_sha256
		   AND outbox_reconciliation_conflicts.candidate_required_agent_role = EXCLUDED.candidate_required_agent_role
		   AND outbox_reconciliation_conflicts.candidate_required_agent_id = EXCLUDED.candidate_required_agent_id
		   AND outbox_reconciliation_conflicts.reason = EXCLUDED.reason
		   AND outbox_reconciliation_conflicts.status = EXCLUDED.status
		   AND outbox_reconciliation_conflicts.detected_at = EXCLUDED.detected_at`,
		c.ID, c.TenantID, c.SourceEventID, int64(c.SourceEventSequence), // #nosec G115 -- JetStream sequence fits PostgreSQL bigint by construction (CWE-190).
		c.SourceEventType, c.IdempotencyKey, c.ExistingOutboxID, c.ExistingDestination,
		c.ExistingEffectLane, c.ExistingPayloadSHA256, c.ExistingRequiredAgentRole, c.ExistingRequiredAgentID,
		c.CandidateDestination, c.CandidateEffectLane, c.CandidatePayloadSHA256,
		c.CandidateRequiredAgentRole, c.CandidateRequiredAgentID, c.Reason, c.Status, c.DetectedAt)
	if err != nil {
		return fmt.Errorf("store: project outbox reconciliation conflict: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: outbox reconciliation conflict source event %s changed after recording", c.SourceEventID)
	}
	return nil
}

// ListOutboxReconciliationConflicts returns the newest quarantined recovery
// incidents for exactly one tenant under FORCE RLS.
func (s *Store) ListOutboxReconciliationConflicts(ctx context.Context, tenantID string, limit int) ([]OutboxReconciliationConflict, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var out []OutboxReconciliationConflict
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id::text, source_event_id, source_event_sequence,
			        source_event_type, idempotency_key, existing_outbox_id,
			        existing_destination, existing_effect_lane, existing_payload_sha256,
			        existing_required_agent_role, existing_required_agent_id,
			        candidate_destination,
			        candidate_effect_lane, candidate_payload_sha256,
			        candidate_required_agent_role, candidate_required_agent_id, reason, status, detected_at
			   FROM outbox_reconciliation_conflicts
			  WHERE tenant_id = $1
			  ORDER BY source_event_sequence DESC, id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c OutboxReconciliationConflict
			if err := rows.Scan(
				&c.ID, &c.TenantID, &c.SourceEventID, &c.SourceEventSequence,
				&c.SourceEventType, &c.IdempotencyKey, &c.ExistingOutboxID,
				&c.ExistingDestination, &c.ExistingEffectLane, &c.ExistingPayloadSHA256,
				&c.ExistingRequiredAgentRole, &c.ExistingRequiredAgentID, &c.CandidateDestination,
				&c.CandidateEffectLane, &c.CandidatePayloadSHA256,
				&c.CandidateRequiredAgentRole, &c.CandidateRequiredAgentID, &c.Reason, &c.Status, &c.DetectedAt,
			); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list outbox reconciliation conflicts: %w", err)
	}
	return out, nil
}
