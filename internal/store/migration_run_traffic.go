// SPDX-License-Identifier: BUSL-1.1

package store

import "context"

// TenantsWithMigrationRunsAwaitingTraffic enumerates tenants holding a running
// or paused migration run that requires observed traffic (X3), so the leader's
// traffic gate can visit each under its own RLS context.
func (s *Store) TenantsWithMigrationRunsAwaitingTraffic(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold a migration run that requires observed traffic so the leader-only traffic gate can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM migration_runs
		  WHERE aggregate->>'require_observed_traffic' = 'true'
		    AND aggregate->>'status' IN ('running', 'paused')
		  ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}
