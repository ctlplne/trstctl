// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// LatestExposureProbes returns the latest live reachability observation of
// each probed NHI endpoint in the tenant (A102): per finding ref, the
// nhi-exposure-probe finding seen last. The read runs inside the tenant's RLS
// scope (AN-1).
func (s *Store) LatestExposureProbes(ctx context.Context, tenantID string, limit int) ([]DiscoveryFinding, error) {
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (ref) id::text, ref, provenance, fingerprint, metadata, last_seen_at
		    FROM discovery_findings
		   WHERE tenant_id = $1 AND kind = 'nhi-exposure-probe'
		   ORDER BY ref, last_seen_at DESC, id DESC
		   LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f := DiscoveryFinding{TenantID: tenantID, Kind: "nhi-exposure-probe"}
			if err := rows.Scan(&f.ID, &f.Ref, &f.Provenance, &f.Fingerprint, &f.Metadata, &f.LastSeenAt); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}
