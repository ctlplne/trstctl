// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ObservedAddress is a network address one of the tenant's own sources saw
// (A212): where a certificate is deployed, an endpoint trstctl verified, one an
// external observer reported, or a destination's verification address.
type ObservedAddress struct {
	Address      string
	Sources      []string
	LastSeen     time.Time
	Observations int
}

// ObservedAddresses returns the distinct addresses the tenant's sources
// recorded since the given time, newest first and bounded. Nothing here is
// resolved or guessed: each value is what a source recorded.
func (s *Store) ObservedAddresses(ctx context.Context, tenantID string, since time.Time, limit int) ([]ObservedAddress, error) {
	var out []ObservedAddress
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`WITH seen AS (
			     SELECT deployment_location AS address, 'certificate_location' AS source,
			            coalesce(last_seen_at, created_at) AS at
			       FROM certificates WHERE tenant_id = $1 AND deployment_location <> ''
			     UNION ALL
			     SELECT address, 'endpoint_verification', last_checked_at
			       FROM endpoint_verifications WHERE tenant_id = $1 AND address <> ''
			     UNION ALL
			     SELECT endpoint, 'external_observation', observed_at
			       FROM external_observations WHERE tenant_id = $1
			     UNION ALL
			     SELECT config->>'verify_address', 'verification_target', created_at
			       FROM deployment_targets WHERE tenant_id = $1 AND coalesce(config->>'verify_address', '') <> ''
			 )
			 SELECT address, array_agg(DISTINCT source ORDER BY source), max(at), count(*)::int
			   FROM seen WHERE at >= $2
			  GROUP BY address
			  ORDER BY max(at) DESC, address
			  LIMIT $3`, tenantID, since, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ObservedAddress
			if err := rows.Scan(&a.Address, &a.Sources, &a.LastSeen, &a.Observations); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
