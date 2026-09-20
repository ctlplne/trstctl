// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/migration"
)

// MigrationRun is the latest event-projected executable wave aggregate.
type MigrationRun struct {
	TenantID          string
	Run               migration.Run
	LastEventSequence uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ApplyMigrationRunRecordedTx is the projector-only writer. A stale replay is
// inert; a newer retained event atomically replaces the complete aggregate.
func (s *Store) ApplyMigrationRunRecordedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	run migration.Run,
	sequence uint64,
	at time.Time,
) error {
	if sequence == 0 {
		return fmt.Errorf("store: migration run event sequence is required")
	}
	aggregate, err := json.Marshal(run)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO migration_runs
		        (tenant_id, id, status, aggregate, last_event_sequence, created_at, updated_at)
		 VALUES ($1, $2, $3, $4::jsonb, $5, $6, $6)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET status = EXCLUDED.status, aggregate = EXCLUDED.aggregate,
		        last_event_sequence = EXCLUDED.last_event_sequence,
		        updated_at = EXCLUDED.updated_at
		  WHERE migration_runs.last_event_sequence < EXCLUDED.last_event_sequence`,
		tenantID, run.ID, string(run.Status), aggregate, int64(sequence), at.UTC()) // #nosec G115 -- JetStream/PostgreSQL event sequence is bounded by bigint (CWE-190)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	for _, wave := range run.Waves {
		for _, member := range wave.Members {
			if member.RollbackSuccessorVerdict != migration.VerdictVerified {
				continue
			}
			if err := s.restoreMigrationCertificateTx(ctx, tx, tenantID, member.Binding, at); err != nil {
				return err
			}
		}
	}
	return nil
}

// restoreMigrationCertificateTx makes the signed, live-verified rollback fact
// and inventory truth one projection transaction. A later issuance wins: an
// old migration event replay cannot reactivate its predecessor over a newer
// active replacement.
func (s *Store) restoreMigrationCertificateTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	binding migration.MemberBinding,
	at time.Time,
) error {
	successorFingerprint := strings.TrimSpace(binding.SuccessorFingerprint)
	var successorStatus, replacesID string
	if successorFingerprint != "" {
		if err := tx.QueryRow(ctx,
			`SELECT status, COALESCE(replaces_id::text, '')
		   FROM certificates
		  WHERE tenant_id = $1 AND fingerprint = $2`,
			tenantID, successorFingerprint).Scan(&successorStatus, &replacesID); err != nil {
			return fmt.Errorf("store: load migration successor for rollback: %w", err)
		}
	}
	if successorFingerprint != "" && replacesID != binding.PredecessorCertificateID {
		return fmt.Errorf("store: migration successor does not replace its immutable predecessor")
	}
	var newerActive bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM certificates
			 WHERE tenant_id = $1 AND replaces_id = $2::uuid
			   AND fingerprint <> $3 AND status = 'active'
		)`, tenantID, binding.PredecessorCertificateID, successorFingerprint).Scan(&newerActive); err != nil {
		return err
	}
	if newerActive {
		return nil
	}
	if successorStatus == "active" {
		if _, err := tx.Exec(ctx,
			`UPDATE certificates
			    SET status = 'superseded', renewed_at = $4
			  WHERE tenant_id = $1 AND fingerprint = $2 AND replaces_id = $3::uuid
			    AND status = 'active'`,
			tenantID, successorFingerprint, binding.PredecessorCertificateID, at.UTC()); err != nil {
			return err
		}
	}
	var predecessorStatus string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM certificates
		  WHERE tenant_id = $1 AND id = $2::uuid AND fingerprint = $3`,
		tenantID, binding.PredecessorCertificateID, binding.PredecessorFingerprint).Scan(&predecessorStatus); err != nil {
		return fmt.Errorf("store: load migration predecessor for rollback: %w", err)
	}
	if successorFingerprint == "" && predecessorStatus != "active" {
		return fmt.Errorf("store: migration rollback has no exact successor and predecessor is %q", predecessorStatus)
	}
	switch predecessorStatus {
	case "active":
		return nil
	case "superseded":
		tag, err := tx.Exec(ctx,
			`UPDATE certificates
			    SET status = 'active', renewed_at = NULL
			  WHERE tenant_id = $1 AND id = $2::uuid AND fingerprint = $3
			    AND status = 'superseded'`,
			tenantID, binding.PredecessorCertificateID, binding.PredecessorFingerprint)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("store: migration predecessor changed during rollback projection")
		}
		return nil
	default:
		return fmt.Errorf("store: migration predecessor status %q cannot be restored", predecessorStatus)
	}
}

// GetMigrationRun loads one tenant's projected run.
func (s *Store) GetMigrationRun(ctx context.Context, tenantID, id string) (MigrationRun, error) {
	var (
		out       MigrationRun
		aggregate []byte
		sequence  int64
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, aggregate, last_event_sequence, created_at, updated_at
			   FROM migration_runs
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&out.TenantID, &aggregate, &sequence, &out.CreatedAt, &out.UpdatedAt)
	})
	if err != nil {
		return MigrationRun{}, err
	}
	if err := json.Unmarshal(aggregate, &out.Run); err != nil {
		return MigrationRun{}, fmt.Errorf("store: decode migration run %s: %w", id, err)
	}
	out.LastEventSequence = uint64(sequence) // #nosec G115 -- positive bigint constrained by migration (CWE-190)
	return out, nil
}

// MigrationRunForUpdateTx locks one aggregate so concurrent signed receipts
// cannot each advance from the same predecessor and overwrite one another.
func (s *Store) MigrationRunForUpdateTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (MigrationRun, error) {
	var (
		out       MigrationRun
		aggregate []byte
		sequence  int64
	)
	err := tx.QueryRow(ctx,
		`SELECT tenant_id::text, aggregate, last_event_sequence, created_at, updated_at
		   FROM migration_runs
		  WHERE tenant_id = $1 AND id = $2
		  FOR UPDATE`, tenantID, id).
		Scan(&out.TenantID, &aggregate, &sequence, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return MigrationRun{}, err
	}
	if err := json.Unmarshal(aggregate, &out.Run); err != nil {
		return MigrationRun{}, fmt.Errorf("store: decode locked migration run %s: %w", id, err)
	}
	out.LastEventSequence = uint64(sequence) // #nosec G115 -- positive bigint constrained by migration (CWE-190)
	return out, nil
}

// ListMigrationRuns returns newest activity first for the tenant console.
func (s *Store) ListMigrationRuns(ctx context.Context, tenantID string, limit int) ([]MigrationRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var out []MigrationRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, aggregate, last_event_sequence, created_at, updated_at
			   FROM migration_runs
			  WHERE tenant_id = $1
			  ORDER BY updated_at DESC, id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				item      MigrationRun
				aggregate []byte
				sequence  int64
			)
			if err := rows.Scan(&item.TenantID, &aggregate, &sequence, &item.CreatedAt, &item.UpdatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(aggregate, &item.Run); err != nil {
				return err
			}
			item.LastEventSequence = uint64(sequence) // #nosec G115 -- positive bigint constrained by migration (CWE-190)
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}
