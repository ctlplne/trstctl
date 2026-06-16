package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// APITokenRecord is a stored API token: its identity, scopes, and expiry, plus
// the hash of its secret. The secret itself is never stored.
type APITokenRecord struct {
	ID        string
	TenantID  string
	TokenHash string
	Subject   string
	Scopes    []string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// CreateAPIToken inserts a token in its tenant context (RLS-enforced), with a
// server-generated id. The caller supplies the precomputed token hash.
func (s *Store) CreateAPIToken(ctx context.Context, r APITokenRecord) (APITokenRecord, error) {
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	err := s.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, scopes, expires_at)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
			 RETURNING id::text, created_at`,
			r.TenantID, r.TokenHash, r.Subject, scopes, r.ExpiresAt).Scan(&r.ID, &r.CreatedAt)
	})
	return r, err
}

// LookupAPITokenByHash finds a token by its hash. Authentication runs before any
// tenant context is known, so this is a system operation (the token's hash is a
// globally unique, high-entropy secret); it returns the token's tenant. It
// returns pgx.ErrNoRows (see IsNotFound) when no such token exists.
func (s *Store) LookupAPITokenByHash(ctx context.Context, hash string) (APITokenRecord, error) {
	var r APITokenRecord
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — auth runs before any tenant is known; the lookup is keyed by the globally-unique, high-entropy token hash and returns the owning tenant. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at
		   FROM api_tokens WHERE token_hash = $1`, hash).
		Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt)
	return r, err
}
