package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrCredentialNotFound is returned by GetCredential when no sealed credential
// matches.
var ErrCredentialNotFound = errors.New("store: credential not found")

// Credential is a sealed (envelope-encrypted) secret at rest (R3.1). Sealed holds
// ciphertext only — the plaintext never lives in the store. It is identified
// within a tenant by (Scope, Ref, Name), e.g. ("connector","target-1","password").
type Credential struct {
	ID        string
	TenantID  string
	Scope     string
	Ref       string
	Name      string
	Sealed    []byte // envelope-encrypted ciphertext; never plaintext
	CreatedAt time.Time
}

// PutCredential stores or replaces a sealed credential in its tenant context
// (AN-1). Sealed must already be ciphertext.
func (s *Store) PutCredential(ctx context.Context, c Credential) error {
	return s.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, scope, ref, name) DO UPDATE
			    SET sealed = EXCLUDED.sealed, updated_at = now()`,
			c.TenantID, c.Scope, c.Ref, c.Name, c.Sealed)
		return err
	})
}

// GetCredential loads a sealed credential in its tenant context (AN-1). It
// returns ErrCredentialNotFound when absent.
func (s *Store) GetCredential(ctx context.Context, tenantID, scope, ref, name string) (Credential, error) {
	var c Credential
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, scope, ref, name, sealed, created_at
			   FROM credentials
			  WHERE tenant_id = $1 AND scope = $2 AND ref = $3 AND name = $4`,
			tenantID, scope, ref, name).
			Scan(&c.ID, &c.TenantID, &c.Scope, &c.Ref, &c.Name, &c.Sealed, &c.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrCredentialNotFound
	}
	return c, err
}

// DeleteCredential removes a sealed credential in its tenant context (AN-1).
func (s *Store) DeleteCredential(ctx context.Context, tenantID, scope, ref, name string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM credentials WHERE tenant_id = $1 AND scope = $2 AND ref = $3 AND name = $4`,
			tenantID, scope, ref, name)
		return err
	})
}
