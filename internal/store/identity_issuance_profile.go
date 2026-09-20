// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// IdentityInitialIssuance locates the accepted issuance event in bounded,
// tenant-scoped history. The caller must verify the original event envelope;
// the projection is an index, not authority to choose a certificate policy.
func (s *Store) IdentityInitialIssuance(ctx context.Context, tenantID, identityID string) (IdentityTransition, bool, error) {
	var result IdentityTransition
	count := 0
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq, idempotency_key FROM identity_transitions
		 WHERE tenant_id=$1 AND identity_id=$2 AND event_type='identity.issued'
		 AND from_state='requested' AND to_state='issued' ORDER BY seq LIMIT 2`, tenantID, identityID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			count++
			if err := rows.Scan(&result.Seq, &result.IdempotencyKey); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return IdentityTransition{}, false, err
	}
	if count > 1 {
		return IdentityTransition{}, false, fmt.Errorf("store: identity %s has ambiguous initial issuance history", identityID)
	}
	result.IdentityID = identityID
	return result, count == 1, nil
}
