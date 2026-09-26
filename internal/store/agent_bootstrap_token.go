// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// BootstrapTokenRecord is a stored agent bootstrap token: the hash of its secret,
// the tenant that authorized it, an optional allowed agent identity, and its
// expiry. The secret itself is never stored (it is shown once at mint).
type BootstrapTokenRecord struct {
	ID              string
	TenantID        string
	TokenHash       string
	AllowedIdentity string
	// GrantedRoles is the capability grant an operator attached at mint (epic A2):
	// "host", "network", or both. It is stamped into the issued certificate at
	// redemption. Empty means host-only.
	GrantedRoles []string
	ExpiresAt    time.Time
	UsedAt       *time.Time
	CreatedAt    time.Time
}

// CreateBootstrapToken inserts a one-time agent bootstrap token bound to its
// tenant (RLS-enforced), with a server-generated id (WIRE-003 / AN-1). The caller
// supplies the precomputed token hash; the raw secret is never persisted. This
// runs under the authorizing tenant's RLS context so the token cannot be minted
// for a tenant the caller is not acting as.
func (s *Store) CreateBootstrapToken(ctx context.Context, r BootstrapTokenRecord) (BootstrapTokenRecord, error) {
	err := s.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO agent_bootstrap_tokens
			     (id, tenant_id, token_hash, allowed_identity, granted_roles, expires_at)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4::text[], $5)
			 RETURNING id::text, created_at`,
			r.TenantID, r.TokenHash, r.AllowedIdentity, roleArray(r.GrantedRoles), r.ExpiresAt).
			Scan(&r.ID, &r.CreatedAt)
	})
	return r, err
}

// RedeemBootstrapToken atomically consumes a one-time bootstrap token by its hash
// and returns the record (carrying the authorizing tenant and any allowed
// identity). Redemption is a system operation — the tenant is not known until the
// token resolves (the hash is a globally-unique, high-entropy secret), exactly
// like API-token authentication.
//
// Single-use is enforced by the conditional UPDATE itself: it sets used_at only
// when the row is currently unused AND unexpired, and RETURNs only then. So a
// token redeemed once — on ANY instance, and surviving a restart because the row
// is durable — is rejected on every later attempt (the UPDATE matches no row and
// the query returns pgx.ErrNoRows, surfaced via IsNotFound). This replaces the
// process-local map[string]bool that lost tokens on restart and could not be
// shared across instances (WIRE-003).
func (s *Store) RedeemBootstrapToken(ctx context.Context, tokenHash string) (BootstrapTokenRecord, error) {
	var r BootstrapTokenRecord
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — agent bootstrap runs before any tenant is known; the lookup is keyed by a globally-unique, high-entropy one-time token hash and returns the owning tenant. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`UPDATE agent_bootstrap_tokens
		    SET used_at = now()
		  WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING id::text, tenant_id::text, token_hash, allowed_identity,
		          granted_roles, expires_at, used_at, created_at`,
		tokenHash).
		Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.AllowedIdentity,
			&r.GrantedRoles, &r.ExpiresAt, &r.UsedAt, &r.CreatedAt)
	return r, err
}

// ValidateBootstrapTokenRedemption runs after tenant admission is held. It
// requires the same consumed, unexpired row that authenticated the operation;
// a tenant UUID alone cannot prove that a pre-erasure redemption is still live.
func (s *Store) ValidateBootstrapTokenRedemption(ctx context.Context, tenantID, tokenID, tokenHash string) error {
	if tenantID == "" || tokenID == "" || tokenHash == "" {
		return pgx.ErrNoRows
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_bootstrap_tokens
			WHERE tenant_id=$1 AND id=$2 AND token_hash=$3 AND used_at IS NOT NULL AND expires_at > now())`,
			tenantID, tokenID, tokenHash).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// roleArray normalizes a grant for storage. A nil slice would be written as SQL
// NULL against a NOT NULL column; an empty array is the honest representation of
// "host-only", which is what no grant means.
func roleArray(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
}

// NOTE: a background purge of used/expired bootstrap tokens (to keep the table
// bounded, mirroring the idempotency-key GC) is a follow-up. It is safe to defer:
// the migration indexes expires_at, an expired token is already non-redeemable
// (RedeemBootstrapToken requires expires_at > now()), and tokens are short-lived
// (DefaultTokenTTL), so the table does not grow unbounded in normal use.
