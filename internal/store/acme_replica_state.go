// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrACMENonceLimit is a nonce refused because the tenant already holds its
// limit of live ACME nonces (P15-L7).
var ErrACMENonceLimit = errors.New("store: the tenant's live ACME nonces are at their limit")

// MintACMENonce records a nonce, by its digest, that any replica may redeem
// once until it expires (P15-L7). Each call first clears up to 100 of the
// tenant's expired nonces and finalize claims. With limit > 0 the tenant holds
// at most limit live nonces; mints in flight at the same moment may each pass
// the count.
func (s *Store) MintACMENonce(ctx context.Context, tenantID, digest string, expires time.Time, limit int) error {
	if tenantID == "" || digest == "" || expires.IsZero() {
		return fmt.Errorf("store: MintACMENonce requires a tenant, digest and expiry (AN-1)")
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM acme_nonces
			WHERE ctid IN (SELECT ctid FROM acme_nonces WHERE tenant_id = $1 AND expires_at <= now() LIMIT 100)`, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM acme_finalize_claims
			WHERE ctid IN (SELECT ctid FROM acme_finalize_claims WHERE tenant_id = $1 AND claimed_until <= now() LIMIT 100)`, tenantID); err != nil {
			return err
		}
		if limit > 0 {
			var live int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM acme_nonces
				WHERE tenant_id = $1 AND expires_at > now() LIMIT $2) AS live`, tenantID, limit).Scan(&live); err != nil {
				return err
			}
			if live >= limit {
				return ErrACMENonceLimit
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO acme_nonces (tenant_id, nonce_digest, expires_at) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, nonce_digest) DO NOTHING`, tenantID, digest, expires.UTC())
		return err
	})
}

// RedeemACMENonce takes a live nonce once, on whichever replica it arrives
// (P15-L7): it reports false for a nonce never minted, already redeemed or
// expired.
func (s *Store) RedeemACMENonce(ctx context.Context, tenantID, digest string) (bool, error) {
	if tenantID == "" || digest == "" {
		return false, fmt.Errorf("store: RedeemACMENonce requires a tenant and digest (AN-1)")
	}
	redeemed := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM acme_nonces WHERE tenant_id = $1 AND nonce_digest = $2 AND expires_at > now()`,
			tenantID, digest)
		if err != nil {
			return err
		}
		redeemed = tag.RowsAffected() == 1
		return nil
	})
	return redeemed, err
}

// ClaimACMEFinalize claims an order's one finalize for holder until until
// (P15-L7): it reports false while another holder's claim is live; a claim
// whose holder stopped expires and may be taken over.
func (s *Store) ClaimACMEFinalize(ctx context.Context, tenantID, orderID, holder string, until time.Time) (bool, error) {
	if tenantID == "" || orderID == "" || holder == "" || until.IsZero() {
		return false, fmt.Errorf("store: ClaimACMEFinalize requires a tenant, order, holder and lease (AN-1)")
	}
	claimed := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO acme_finalize_claims (tenant_id, order_id, holder, claimed_until) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, order_id) DO UPDATE SET holder = EXCLUDED.holder, claimed_until = EXCLUDED.claimed_until
			 WHERE acme_finalize_claims.claimed_until <= now() OR acme_finalize_claims.holder = EXCLUDED.holder`,
			tenantID, orderID, holder, until.UTC())
		if err != nil {
			return err
		}
		claimed = tag.RowsAffected() == 1
		return nil
	})
	return claimed, err
}

// ReleaseACMEFinalize drops holder's claim on an order, so a finalize that
// did not issue can be retried at once on any replica.
func (s *Store) ReleaseACMEFinalize(ctx context.Context, tenantID, orderID, holder string) error {
	if tenantID == "" || orderID == "" || holder == "" {
		return fmt.Errorf("store: ReleaseACMEFinalize requires a tenant, order and holder (AN-1)")
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM acme_finalize_claims WHERE tenant_id = $1 AND order_id = $2 AND holder = $3`,
			tenantID, orderID, holder)
		return err
	})
}
