// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// IdentityFirstEnrollment returns the identity's earliest certificate, revoked
// or not, and the enrollment path recorded for it (A244-L4): empty when that
// certificate was issued before paths were kept, or the identity has none.
func (s *Store) IdentityFirstEnrollment(ctx context.Context, tenantID, identityID string) (certificateID, protocol string, err error) {
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx, `SELECT id::text, enrollment_protocol FROM certificates
   WHERE tenant_id=$1 AND `+identityRevocationBinding+`
   ORDER BY created_at,id LIMIT 1`, tenantID, identityID).Scan(&certificateID, &protocol)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		return scanErr
	})
	return certificateID, protocol, err
}
