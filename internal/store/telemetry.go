// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
)

// TelemetryCredentialCounts returns cross-tenant aggregate credential totals for
// the opt-in product telemetry reporter. It intentionally returns only type ->
// count; callers bucket the numbers before any payload leaves the process.
func (s *Store) TelemetryCredentialCounts(ctx context.Context) (map[string]int, error) {
	counts := map[string]int{}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: opt-in instance telemetry reports only aggregate credential buckets, never tenant rows or tenant_id values.
		`SELECT kind, count(*)::bigint
		   FROM identities
		  WHERE tenant_id IS NOT NULL
		  GROUP BY kind`)
	if err != nil {
		return nil, fmt.Errorf("count identities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n int64
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("scan identity count: %w", err)
		}
		if err := addTelemetryCount(counts, kind, n); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("count identities: %w", err)
	}

	for _, q := range []struct {
		kind string
		sql  string
	}{
		{string(KindSecret), `SELECT count(*)::bigint FROM secret_store WHERE tenant_id IS NOT NULL`},
		{string(KindAPIKey), `SELECT count(*)::bigint FROM api_tokens WHERE tenant_id IS NOT NULL AND revoked_at IS NULL`},
		{string(KindSSHKey), `SELECT count(*)::bigint FROM ssh_keys WHERE tenant_id IS NOT NULL`},
	} {
		var n int64
		if err := s.pool.QueryRow(ctx,
			//trstctl:system-query — cross-tenant by design: opt-in instance telemetry reads only aggregate credential counts and emits bucketed non-tenant data.
			q.sql).Scan(&n); err != nil {
			return nil, fmt.Errorf("count %s: %w", q.kind, err)
		}
		if err := addTelemetryCount(counts, q.kind, n); err != nil {
			return nil, err
		}
	}
	return counts, nil
}

func addTelemetryCount(counts map[string]int, kind string, n int64) error {
	maxInt := int64(int(^uint(0) >> 1))
	if n < 0 || n > maxInt {
		return fmt.Errorf("telemetry count for %s out of range: %d", kind, n)
	}
	counts[kind] += int(n)
	return nil
}
