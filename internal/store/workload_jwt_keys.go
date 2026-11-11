// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// WorkloadJWTKeyRotation is one rotation of the workload JWT signing key
// (N5-L3): generation Generation (2 and up) is published at PublishedAt, signs
// from ActivatesAt, and the generation before it stays published until
// PreviousRetiresAt.
type WorkloadJWTKeyRotation struct {
	Generation        int
	KeyID             string
	PublishedAt       time.Time
	ActivatesAt       time.Time
	PreviousRetiresAt time.Time
}

// ApplyWorkloadJWTKeyRotatedTx projects workload.jwt_key.rotated. A replay of
// a generation already recorded changes nothing.
func (s *Store) ApplyWorkloadJWTKeyRotatedTx(ctx context.Context, tx pgx.Tx, tenantID string, r WorkloadJWTKeyRotation, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: a workload JWT key rotation needs a positive int64 sequence")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO workload_jwt_keys (tenant_id, generation, key_id, published_at, activates_at, previous_retires_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, generation) DO NOTHING`,
		tenantID, r.Generation, r.KeyID, r.PublishedAt.UTC(), r.ActivatesAt.UTC(), r.PreviousRetiresAt.UTC(), int64(sequence)) // #nosec G115 -- bounded to int64 above (CWE-190)
	return err
}

// WorkloadJWTKeyRotations lists the tenant's rotations, oldest first.
func (s *Store) WorkloadJWTKeyRotations(ctx context.Context, tenantID string) ([]WorkloadJWTKeyRotation, error) {
	var out []WorkloadJWTKeyRotation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT generation, key_id, published_at, activates_at, previous_retires_at
			  FROM workload_jwt_keys WHERE tenant_id = $1 ORDER BY generation`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r WorkloadJWTKeyRotation
			if err := rows.Scan(&r.Generation, &r.KeyID, &r.PublishedAt, &r.ActivatesAt, &r.PreviousRetiresAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
