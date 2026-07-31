// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const (
	IdempotencyResultCodecRawV0                = "raw-v0"
	IdempotencyResultCodecSealedRowV1          = "sealed-row-v1"
	IdempotencyResultCodecSealedDynamicLeaseV1 = "sealed-dynamic-lease-v1"
)

// UnprotectedIdempotencyResult is one callback-scoped migration record. Result
// may contain credential bytes and must be wiped by the caller after use.
type UnprotectedIdempotencyResult struct {
	Key     string
	Binding string
	Codec   string
	Result  []byte
}

// IdempotencyResultProtectionStatus exposes counts only, never result bytes.
type IdempotencyResultProtectionStatus struct {
	TenantID           string
	RawV0              int64
	LegacyDynamicLease int64
	SealedRowV1        int64
	Pending            int64
	Indeterminate      int64
}

// RemainingLegacy is the number of completed rows still using a migration-only
// codec.
func (s IdempotencyResultProtectionStatus) RemainingLegacy() int64 {
	return s.RawV0 + s.LegacyDynamicLease
}

// ListUnprotectedIdempotencyResults returns one key-ordered tenant page under
// RLS. The cursor is exclusive, making every successful compare-and-swap batch
// resumable without offset drift.
func (s *Store) ListUnprotectedIdempotencyResults(
	ctx context.Context,
	tenantID, afterKey string,
	limit int,
) ([]UnprotectedIdempotencyResult, error) {
	if tenantID == "" {
		return nil, errors.New("store: idempotency result migration requires tenant id (AN-1)")
	}
	if limit <= 0 || limit > 1000 {
		return nil, errors.New("store: idempotency result migration limit must be between 1 and 1000")
	}
	var out []UnprotectedIdempotencyResult
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT key, request_binding, result_codec, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1
			    AND key > $2
			    AND status = 'completed'
			    AND result_codec IN ('raw-v0', 'sealed-dynamic-lease-v1')
			  ORDER BY key
			  LIMIT $3`,
			tenantID, afterKey, limit)
		if err != nil {
			return fmt.Errorf("store: list unprotected idempotency results: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var row UnprotectedIdempotencyResult
			if err := rows.Scan(&row.Key, &row.Binding, &row.Codec, &row.Result); err != nil {
				return fmt.Errorf("store: scan unprotected idempotency result: %w", err)
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// ReplaceUnprotectedIdempotencyResult atomically replaces exactly the row that
// was read. A concurrent status/codec/result change refuses the migration so a
// stale process cannot overwrite a newer canonical response.
func (s *Store) ReplaceUnprotectedIdempotencyResult(
	ctx context.Context,
	tenantID string,
	before UnprotectedIdempotencyResult,
	protected []byte,
) (bool, error) {
	if tenantID == "" || before.Key == "" || len(protected) == 0 {
		return false, errors.New("store: protected idempotency replacement requires tenant, key, and ciphertext")
	}
	if before.Codec != IdempotencyResultCodecRawV0 &&
		before.Codec != IdempotencyResultCodecSealedDynamicLeaseV1 {
		return false, fmt.Errorf("store: codec %q is not migration-only", before.Codec)
	}
	var replaced bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			    SET result_codec = 'sealed-row-v1', result = $6
			  WHERE tenant_id = $1
			    AND key = $2
			    AND request_binding = $3
			    AND status = 'completed'
			    AND result_codec = $4
			    AND result IS NOT DISTINCT FROM $5`,
			tenantID, before.Key, before.Binding, before.Codec, before.Result, protected)
		if err != nil {
			return fmt.Errorf("store: replace unprotected idempotency result: %w", err)
		}
		replaced = tag.RowsAffected() == 1
		return nil
	})
	return replaced, err
}

// IdempotencyResultProtectionStatus returns tenant-scoped counts safe for API,
// metrics, and recovery guidance. It never selects the result column.
func (s *Store) IdempotencyResultProtectionStatus(
	ctx context.Context,
	tenantID string,
) (IdempotencyResultProtectionStatus, error) {
	status := IdempotencyResultProtectionStatus{TenantID: tenantID}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			    count(*) FILTER (WHERE status = 'completed' AND result_codec = 'raw-v0'),
			    count(*) FILTER (WHERE status = 'completed' AND result_codec = 'sealed-dynamic-lease-v1'),
			    count(*) FILTER (WHERE status = 'completed' AND result_codec = 'sealed-row-v1'),
			    count(*) FILTER (WHERE status IN ('pending', 'bound')),
			    count(*) FILTER (WHERE status = 'indeterminate')
			   FROM idempotency_keys
			  WHERE tenant_id = $1`,
			tenantID).Scan(
			&status.RawV0,
			&status.LegacyDynamicLease,
			&status.SealedRowV1,
			&status.Pending,
			&status.Indeterminate,
		)
	})
	return status, err
}
