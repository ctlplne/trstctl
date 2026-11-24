// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ProjectionTenantQuarantined reports whether replay found an immutable event
// whose payload cannot be safely represented in this tenant's read model.
func (s *Store) ProjectionTenantQuarantined(ctx context.Context, tenantID string) (bool, error) {
	var quarantined bool
	err := s.poolFor(ctx).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM projection_tenant_quarantines WHERE tenant_id=$1)`, tenantID).Scan(&quarantined)
	if err != nil {
		return false, fmt.Errorf("store: read projection tenant quarantine: %w", err)
	}
	return quarantined, nil
}

// ProjectionTenantQuarantinedTx sees an offboard deletion staged by atomic
// rebuild before a later registration of the same tenant UUID is replayed.
func (s *Store) ProjectionTenantQuarantinedTx(ctx context.Context, tx pgx.Tx, tenantID string) (bool, error) {
	var quarantined bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM projection_tenant_quarantines WHERE tenant_id=$1)`, tenantID).Scan(&quarantined)
	if err != nil {
		return false, fmt.Errorf("store: read projection tenant quarantine in transaction: %w", err)
	}
	return quarantined, nil
}

// DeleteProjectionTenantQuarantineTx ends the old tenant lifecycle during an
// atomic rebuild. The new registration of this UUID must not inherit its denial.
func (s *Store) DeleteProjectionTenantQuarantineTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return fmt.Errorf("store: delete projection tenant quarantine in transaction: %w", err)
	}
	return nil
}

// RecordProjectionTenantQuarantine keeps the first failed sequence. It writes
// only bounded, fixed diagnostic codes; the event remains the audit source.
// Replaying the same history after a crash is idempotent.
func (s *Store) RecordProjectionTenantQuarantine(ctx context.Context, tenantID string, seq uint64, reasonCode string) error {
	return recordProjectionTenantQuarantine(ctx, s.poolFor(ctx), tenantID, seq, reasonCode)
}

// RecordProjectionTenantQuarantineTx participates in atomic rebuild so a later
// offboard event in that same transaction can erase the marker it just derived.
func (s *Store) RecordProjectionTenantQuarantineTx(ctx context.Context, tx pgx.Tx, tenantID string, seq uint64, reasonCode string) error {
	return recordProjectionTenantQuarantine(ctx, tx, tenantID, seq, reasonCode)
}

type projectionTenantQuarantineWriter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func recordProjectionTenantQuarantine(ctx context.Context, writer projectionTenantQuarantineWriter, tenantID string, seq uint64, reasonCode string) error {
	if !validProjectionTenantQuarantine(tenantID, seq, reasonCode) {
		return fmt.Errorf("store: invalid projection tenant quarantine coordinate")
	}
	_, err := writer.Exec(ctx,
		`INSERT INTO projection_tenant_quarantines (tenant_id, first_failed_seq, reason_code)
		 VALUES ($1,$2,$3) ON CONFLICT (tenant_id) DO NOTHING`, tenantID, int64(seq), reasonCode) // #nosec G115 -- range checked above (CWE-190)
	if err != nil {
		return fmt.Errorf("store: record projection tenant quarantine: %w", err)
	}
	return nil
}

func validProjectionTenantQuarantine(tenantID string, seq uint64, reasonCode string) bool {
	return tenantID != "" && seq > 0 && seq <= math.MaxInt64 &&
		(reasonCode == "nul_text" || reasonCode == "invalid_utf8")
}
