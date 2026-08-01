// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// DiscoveryCoverage is one source's coverage rollup: its kind plus the latest
// completed-run state, projected from the discovery events. The coverage API
// classifies these rows against the observability envelopes at read time.
type DiscoveryCoverage struct {
	TenantID        string
	SourceID        string
	SourceKind      string
	SourceName      string
	LastRunStatus   string
	LastCompletedAt *time.Time
	EventSequence   uint64
}

// ApplyDiscoveryCoverageSourceTx upserts the rollup row for an upserted
// discovery source. Later replays win by event sequence, so an inline apply
// and the durable tailer converge (AN-2 idempotent under at-least-once).
func (s *Store) ApplyDiscoveryCoverageSourceTx(ctx context.Context, tx pgx.Tx, c DiscoveryCoverage) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO discovery_coverage (tenant_id, source_id, source_kind, source_name, event_sequence)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, source_id) DO UPDATE
		SET source_kind = EXCLUDED.source_kind,
		    source_name = EXCLUDED.source_name,
		    event_sequence = GREATEST(discovery_coverage.event_sequence, EXCLUDED.event_sequence)
		WHERE EXCLUDED.event_sequence >= discovery_coverage.event_sequence`,
		c.TenantID, c.SourceID, c.SourceKind, c.SourceName, int64(c.EventSequence)) // #nosec G115 -- event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// ApplyDiscoveryCoverageRunTx folds a completed run into its source's rollup
// row by joining the run row (already applied in this transaction) for the
// source identity. A run for a source with no rollup row yet (replay order)
// creates it from the joined source.
func (s *Store) ApplyDiscoveryCoverageRunTx(ctx context.Context, tx pgx.Tx, tenantID, runID, status string, completedAt time.Time, seq uint64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO discovery_coverage (tenant_id, source_id, source_kind, source_name, last_run_status, last_completed_at, event_sequence)
		SELECT r.tenant_id, r.source_id, s.kind, s.name, $3, $4, $5
		FROM discovery_runs r
		JOIN discovery_sources s ON s.tenant_id = r.tenant_id AND s.id = r.source_id
		WHERE r.tenant_id = $1 AND r.id = $2
		ON CONFLICT (tenant_id, source_id) DO UPDATE
		SET last_run_status = EXCLUDED.last_run_status,
		    last_completed_at = EXCLUDED.last_completed_at,
		    event_sequence = GREATEST(discovery_coverage.event_sequence, EXCLUDED.event_sequence)
		WHERE EXCLUDED.event_sequence >= discovery_coverage.event_sequence`,
		tenantID, runID, status, completedAt, int64(seq)) // #nosec G115 -- event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// ListDiscoveryCoverage returns the tenant's coverage rollup rows ordered by
// kind then source id.
func (s *Store) ListDiscoveryCoverage(ctx context.Context, tenantID string) ([]DiscoveryCoverage, error) {
	var out []DiscoveryCoverage
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id::text, source_id::text, source_kind, source_name, last_run_status, last_completed_at, event_sequence
			FROM discovery_coverage
			WHERE tenant_id = $1
			ORDER BY source_kind, source_id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c DiscoveryCoverage
			var seq int64
			if err := rows.Scan(&c.TenantID, &c.SourceID, &c.SourceKind, &c.SourceName, &c.LastRunStatus, &c.LastCompletedAt, &seq); err != nil {
				return err
			}
			c.EventSequence = uint64(seq) // #nosec G115 -- event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
