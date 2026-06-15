package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrSecretNotFound is returned by GetSecret/RotateSecret when no sealed
// application secret matches (tenant, name).
var ErrSecretNotFound = errors.New("store: secret not found")

// Secret is a sealed (envelope-encrypted) application secret at rest in the served
// secret store (GAP-006 / the served secrets API). Sealed holds ciphertext only —
// the plaintext never lives in the store (AN-8). It is identified within a tenant
// by Name; Version is the monotonic rotation counter. Every operation is
// tenant-scoped under RLS (AN-1).
type Secret struct {
	ID        string
	TenantID  string
	Name      string
	Sealed    []byte // envelope-encrypted ciphertext; never plaintext
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PutSecret stores a NEW sealed application secret (version 1) for (tenant, name).
// It returns ErrSecretExists when the name already exists in the tenant — creation
// is distinct from rotation so a create never silently clobbers an existing secret
// (use RotateSecret to replace). Sealed must already be ciphertext. Tenant-scoped
// under RLS (AN-1).
func (s *Store) PutSecret(ctx context.Context, tenantID, name string, sealed []byte) (Secret, error) {
	var out Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO secret_store (tenant_id, name, sealed, version)
			 VALUES ($1, $2, $3, 1)
			 ON CONFLICT (tenant_id, name) DO NOTHING
			 RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantID, name, sealed).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO NOTHING returned no row: the secret already exists.
		return Secret{}, ErrSecretExists
	}
	if err != nil {
		return Secret{}, err
	}
	out.Sealed = sealed
	return out, nil
}

// ErrSecretExists is returned by PutSecret when a secret with the same name
// already exists in the tenant (create must not clobber; rotate instead).
var ErrSecretExists = errors.New("store: secret already exists")

// GetSecret loads a sealed application secret for (tenant, name). It returns
// ErrSecretNotFound when absent. Tenant-scoped under RLS (AN-1).
func (s *Store) GetSecret(ctx context.Context, tenantID, name string) (Secret, error) {
	var out Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, sealed, version, created_at, updated_at
			   FROM secret_store
			  WHERE tenant_id = $1 AND name = $2`,
			tenantID, name).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Sealed, &out.Version, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Secret{}, ErrSecretNotFound
	}
	return out, err
}

// RotateSecret replaces the sealed value of an existing secret and bumps its
// version (the rotation counter), returning the rotated row. It returns
// ErrSecretNotFound when the secret does not exist — a rotation is an explicit
// in-place replacement of a known secret, never a back-door create. Tenant-scoped
// under RLS (AN-1).
func (s *Store) RotateSecret(ctx context.Context, tenantID, name string, sealed []byte) (Secret, error) {
	var out Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`UPDATE secret_store
			    SET sealed = $3, version = version + 1, updated_at = now()
			  WHERE tenant_id = $1 AND name = $2
			  RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantID, name, sealed).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Secret{}, ErrSecretNotFound
	}
	if err != nil {
		return Secret{}, err
	}
	out.Sealed = sealed
	return out, nil
}

// PurgeSecret removes an application secret for (tenant, name) from the sealed
// secret store. It returns ErrSecretNotFound when nothing was deleted, so the served
// DELETE can answer 404 for an unknown secret rather than a misleading success.
// Tenant-scoped under RLS (AN-1).
//
// The secret store is a PRIMARY sealed-at-rest store (its values are ciphertext that
// cannot be put in the event log, AN-8), not a read-model projection of the event
// log — so it is named Purge, not Delete, to distinguish it from a read-model
// mutator. The metadata change is still event-sourced (the handler emits a
// secret.deleted event, AN-2); only the sealed value lives solely in this store, as
// with the credentials table.
func (s *Store) PurgeSecret(ctx context.Context, tenantID, name string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`DELETE FROM secret_store WHERE tenant_id = $1 AND name = $2`,
			tenantID, name)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrSecretNotFound
		}
		return nil
	})
}

// ListSecretNames returns the names (no values) of the tenant's secrets, ordered by
// name, for the served list endpoint. It NEVER returns the sealed bytes — a list is
// metadata only, so a secret value never leaks through enumeration (AN-8).
// Tenant-scoped under RLS (AN-1).
func (s *Store) ListSecretNames(ctx context.Context, tenantID string, limit int) ([]Secret, error) {
	var out []Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, version, created_at, updated_at
			   FROM secret_store
			  WHERE tenant_id = $1
			  ORDER BY name
			  LIMIT $2`,
			tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Secret
			if err := rows.Scan(&m.ID, &m.TenantID, &m.Name, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}
