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
	return s.latestFindingsByRef(ctx, tenantID, "nhi-exposure-probe", limit)
}

// LatestAttackPathFindings returns the latest provider-native attack-path
// verdict of each validated NHI endpoint (A167): per finding ref and source
// (A167-L4), the nhi-attack-path finding seen last.
func (s *Store) LatestAttackPathFindings(ctx context.Context, tenantID string, limit int) ([]DiscoveryFinding, error) {
	// A167-L4: the latest verdict per address from each source, so a source
	// whose account does not hold the address cannot hide the verdict of the
	// one that does; the reader chooses among them.
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (ref, source_id) id::text, ref, COALESCE(source_id::text, ''), provenance, fingerprint, metadata, last_seen_at
		    FROM discovery_findings
		   WHERE tenant_id = $1 AND kind = 'nhi-attack-path'
		   ORDER BY ref, source_id, last_seen_at DESC, id DESC
		   LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f := DiscoveryFinding{TenantID: tenantID, Kind: "nhi-attack-path"}
			if err := rows.Scan(&f.ID, &f.Ref, &f.SourceID, &f.Provenance, &f.Fingerprint, &f.Metadata, &f.LastSeenAt); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) latestFindingsByRef(ctx context.Context, tenantID, kind string, limit int) ([]DiscoveryFinding, error) {
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (ref) id::text, ref, provenance, fingerprint, metadata, last_seen_at
		    FROM discovery_findings
		   WHERE tenant_id = $1 AND kind = $2
		   ORDER BY ref, last_seen_at DESC, id DESC
		   LIMIT $3`, tenantID, kind, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f := DiscoveryFinding{TenantID: tenantID, Kind: kind}
			if err := rows.Scan(&f.ID, &f.Ref, &f.Provenance, &f.Fingerprint, &f.Metadata, &f.LastSeenAt); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}
