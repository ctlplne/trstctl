// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// FirstMachineCredentialUse records one use of a JWT-style machine credential
// (keyed by a digest, never the token) until it expires, and reports whether
// this was its first use. A key whose record has expired is a new use. Each
// call also clears up to 100 of the tenant's expired records.
func (s *Store) FirstMachineCredentialUse(ctx context.Context, tenantID, method, keyDigest string, expires time.Time) (bool, error) {
	if tenantID == "" || method == "" || keyDigest == "" || expires.IsZero() {
		return false, fmt.Errorf("store: FirstMachineCredentialUse requires a tenant, method, key and expiry (AN-1)")
	}
	first := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM machine_credential_replays
			WHERE ctid IN (SELECT ctid FROM machine_credential_replays
			                WHERE tenant_id = $1 AND expires_at <= now() LIMIT 100)`, tenantID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO machine_credential_replays (tenant_id, method, key_digest, expires_at, used_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (tenant_id, method, key_digest) DO UPDATE SET expires_at = EXCLUDED.expires_at, used_at = now()
			 WHERE machine_credential_replays.expires_at <= now()`,
			tenantID, method, keyDigest, expires.UTC())
		if err != nil {
			return err
		}
		first = tag.RowsAffected() == 1
		return nil
	})
	return first, err
}
