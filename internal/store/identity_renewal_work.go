// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// IdentityRenewalWorkPending is the read-only operator preview check. Execution
// must repeat it under the identity row lock before accepting another renewal.
func (s *Store) IdentityRenewalWorkPending(ctx context.Context, tenantID, identityID string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		pending, err = s.IdentityRenewalWorkPendingTx(ctx, tx, tenantID, identityID)
		return err
	})
	return pending, err
}

// IdentityRenewalWorkPendingTx follows the outbox across CA-to-agent handoff.
// An unsuccessful attempt can leave the identity renewal_failed while the same
// job remains pending or processing. Only terminal jobs release this guard.
// These two destinations carry public identity routing metadata in JSON; other
// outbox payloads may be sealed or use another encoding and are never parsed.
func (s *Store) IdentityRenewalWorkPendingTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM outbox
		WHERE tenant_id = $1 AND status IN ('pending', 'processing')
		AND CASE WHEN destination IN ('ca.renew', 'endpoint.renew')
		THEN convert_from(payload, 'UTF8')::jsonb->>'identity_id' = $2 ELSE false END)`, tenantID, identityID).Scan(&pending)
	return pending, err
}
