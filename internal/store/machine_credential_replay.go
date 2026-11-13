// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrSingleUseLimitReached is a machine login refused because the tenant
// already holds its limit of live single-use records (M4-L2). It is never a
// replay: the token was otherwise accepted and has not been used up.
var ErrSingleUseLimitReached = errors.New("store: the tenant's single-use login records are at their limit")

// SingleUseLimitError is ErrSingleUseLimitReached with the limit and when the
// tenant's oldest live record expires, freeing room.
type SingleUseLimitError struct {
	Limit   int
	RetryAt time.Time
}

func (e *SingleUseLimitError) Error() string {
	return fmt.Sprintf("%v (%d live records; the oldest expires at %s)", ErrSingleUseLimitReached, e.Limit, e.RetryAt.UTC().Format(time.RFC3339))
}

// Is makes errors.Is(err, ErrSingleUseLimitReached) true.
func (e *SingleUseLimitError) Is(target error) bool { return target == ErrSingleUseLimitReached }

// FirstMachineCredentialUse records one use of a JWT-style machine credential
// (keyed by a digest, never the token) until it expires, and reports whether
// this was its first use. A key whose record has expired is a new use. Each
// call also clears up to 100 of the tenant's expired records. With limit > 0
// the tenant holds at most limit live records (M4-L2): a new key beyond them
// is refused with a *SingleUseLimitError until older ones expire, while a
// replayed key is still reported as a replay. Logins in flight at the same
// moment may each pass the count, so the limit can be exceeded by them.
func (s *Store) FirstMachineCredentialUse(ctx context.Context, tenantID, method, keyDigest string, expires time.Time, limit int) (bool, error) {
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
		if limit > 0 {
			var replayed bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM machine_credential_replays
				WHERE tenant_id = $1 AND method = $2 AND key_digest = $3 AND expires_at > now())`,
				tenantID, method, keyDigest).Scan(&replayed); err != nil {
				return err
			}
			if replayed {
				return nil
			}
			var live int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM machine_credential_replays
				WHERE tenant_id = $1 AND expires_at > now() LIMIT $2) AS live`, tenantID, limit).Scan(&live); err != nil {
				return err
			}
			if live >= limit {
				var oldest *time.Time
				if err := tx.QueryRow(ctx, `SELECT min(expires_at) FROM machine_credential_replays
					WHERE tenant_id = $1 AND expires_at > now()`, tenantID).Scan(&oldest); err != nil {
					return err
				}
				out := &SingleUseLimitError{Limit: limit, RetryAt: time.Now().UTC()}
				if oldest != nil {
					out.RetryAt = oldest.UTC()
				}
				return out
			}
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
