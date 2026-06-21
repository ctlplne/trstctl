package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

// APITokenRecord is a stored API token: its identity, scopes, and expiry, plus
// the hash of its secret. The secret itself is never stored.
type APITokenRecord struct {
	ID               string
	TenantID         string
	TokenHash        string
	Subject          string
	Scopes           []string
	ExpiresAt        *time.Time
	CreatedAt        time.Time
	RevokedAt        *time.Time
	RevokedBy        string
	RevocationReason string
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
			`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, subject_ref, scopes, expires_at)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
			 RETURNING id::text, created_at`,
			r.TenantID, r.TokenHash, r.Subject, privacy.SubjectRef(r.TenantID, r.Subject), scopes, r.ExpiresAt).Scan(&r.ID, &r.CreatedAt)
	})
	return r, err
}

// ApplyAPITokenCreatedTx projects an api_token.created event into the token read
// model. The token secret itself is never in this row or the event; only its
// lookup hash is stored.
func (s *Store) ApplyAPITokenCreatedTx(ctx context.Context, tx pgx.Tx, r APITokenRecord) error {
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, subject_ref, scopes, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (id) DO UPDATE
		    SET token_hash = EXCLUDED.token_hash,
		        subject = EXCLUDED.subject,
		        subject_ref = EXCLUDED.subject_ref,
		        scopes = EXCLUDED.scopes,
		        expires_at = EXCLUDED.expires_at,
		        created_at = EXCLUDED.created_at,
		        revoked_at = NULL,
		        revoked_by = '',
		        revocation_reason = ''`,
		r.ID, r.TenantID, r.TokenHash, r.Subject, privacy.SubjectRef(r.TenantID, r.Subject), scopes, r.ExpiresAt, r.CreatedAt)
	return err
}

// ApplyAPITokenRevokedTx projects an api_token.revoked event. Replaying it is
// idempotent: the first revocation timestamp wins.
func (s *Store) ApplyAPITokenRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, revokedBy, reason string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET revoked_at = COALESCE(revoked_at, $3),
		        revoked_by = CASE WHEN revoked_by = '' THEN $4 ELSE revoked_by END,
		        revocation_reason = CASE WHEN revocation_reason = '' THEN $5 ELSE revocation_reason END
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, revokedBy, reason)
	return err
}

// ApplyAPITokensRevokedForSubjectTx projects member offboarding by revoking every
// active API token owned by the subject.
func (s *Store) ApplyAPITokensRevokedForSubjectTx(ctx context.Context, tx pgx.Tx, tenantID, subject, revokedBy, reason string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET revoked_at = COALESCE(revoked_at, $3),
		        revoked_by = CASE WHEN revoked_by = '' THEN $4 ELSE revoked_by END,
		        revocation_reason = CASE WHEN revocation_reason = '' THEN $5 ELSE revocation_reason END
		  WHERE tenant_id = $1 AND subject = $2 AND revoked_at IS NULL`,
		tenantID, subject, at, revokedBy, reason)
	return err
}

// GetAPIToken loads one token row in its tenant context.
func (s *Store) GetAPIToken(ctx context.Context, tenantID, id string) (APITokenRecord, error) {
	var r APITokenRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
			        revoked_at, revoked_by, revocation_reason
			   FROM api_tokens WHERE tenant_id = $1 AND id = $2`,
			tenantID, id).Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason)
	})
	return r, err
}

// CountActiveAPITokensForSubject returns how many bearer credentials offboarding
// will revoke for subject.
func (s *Store) CountActiveAPITokensForSubject(ctx context.Context, tenantID, subject string) (int, error) {
	var n int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject = $2 AND revoked_at IS NULL`,
			tenantID, subject).Scan(&n)
	})
	return n, err
}

// ListAPITokensPage returns a tenant-scoped page of token metadata. It never
// returns token secrets.
func (s *Store) ListAPITokensPage(ctx context.Context, tenantID, afterID, subject string, includeRevoked bool, limit int) ([]APITokenRecord, error) {
	var out []APITokenRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
			        revoked_at, revoked_by, revocation_reason
			   FROM api_tokens
			  WHERE tenant_id = $1
			    AND id > $2
			    AND ($3 = '' OR subject = $3)
			    AND ($4 OR revoked_at IS NULL)
			  ORDER BY id LIMIT $5`,
			tenantID, afterID, subject, includeRevoked, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r APITokenRecord
			if err := rows.Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// LookupAPITokenByHash finds a token by its hash. Authentication runs before any
// tenant context is known, so this is a system operation (the token's hash is a
// globally unique, high-entropy secret); it returns the token's tenant. It
// returns pgx.ErrNoRows (see IsNotFound) when no such token exists.
func (s *Store) LookupAPITokenByHash(ctx context.Context, hash string) (APITokenRecord, error) {
	var r APITokenRecord
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — auth runs before any tenant is known; the lookup is keyed by the globally-unique, high-entropy token hash and returns the owning tenant. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
		        revoked_at, revoked_by, revocation_reason
		   FROM api_tokens WHERE token_hash = $1 AND revoked_at IS NULL`, hash).
		Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason)
	return r, err
}
