package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrSecretNotFound is returned by GetSecret/RotateSecret when no sealed
// application secret matches (tenant, name).
var ErrSecretNotFound = errors.New("store: secret not found")

// ErrSecretShareNotFound is returned when a one-time share token hash is absent,
// expired, or already consumed.
var ErrSecretShareNotFound = errors.New("store: secret share not found")

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

// SecretVersion is one sealed historical version of an application secret. Sealed
// is ciphertext only; opening it happens through the crypto/seal boundary.
type SecretVersion struct {
	TenantID             string
	Name                 string
	Version              int
	Sealed               []byte
	WrittenAt            time.Time
	RecoveredFromVersion *int
}

// SecretImportEntry is one already-sealed secret to import atomically into the
// served secret store.
type SecretImportEntry struct {
	Name   string
	Sealed []byte
}

// SecretShare is a durable, tenant-scoped one-time share row. TokenHash is a
// SHA-256 hex digest of the bearer token; Sealed is ciphertext only.
type SecretShare struct {
	TenantID  string
	TokenHash string
	ShareID   string
	Sealed    []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PutSecretShare stores a sealed one-time share keyed by SHA-256(token). It never
// stores the bearer token or plaintext. Tenant-scoped under RLS (AN-1).
func (s *Store) PutSecretShare(ctx context.Context, tenantID, tokenHash, shareID string, sealed []byte, expiresAt time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_shares (tenant_id, token_sha256, share_id, sealed, expires_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			tenantID, tokenHash, shareID, sealed, expiresAt.UTC())
		return err
	})
}

// ConsumeSecretShare atomically deletes and returns a still-valid one-time share.
// DELETE ... RETURNING makes a successful redemption single-use under concurrency.
// Expired shares are removed opportunistically and reported as not found.
func (s *Store) ConsumeSecretShare(ctx context.Context, tenantID, tokenHash string, now time.Time) (SecretShare, error) {
	var out SecretShare
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`DELETE FROM secret_shares
			  WHERE tenant_id = $1 AND token_sha256 = $2 AND expires_at > $3
			  RETURNING tenant_id::text, token_sha256, share_id, sealed, expires_at, created_at`,
			tenantID, tokenHash, now.UTC()).
			Scan(&out.TenantID, &out.TokenHash, &out.ShareID, &out.Sealed, &out.ExpiresAt, &out.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			_, _ = tx.Exec(ctx,
				`DELETE FROM secret_shares
				  WHERE tenant_id = $1 AND token_sha256 = $2 AND expires_at <= $3`,
				tenantID, tokenHash, now.UTC())
			return err
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretShare{}, ErrSecretShareNotFound
	}
	return out, err
}

// PutSecret stores a NEW sealed application secret (version 1) for (tenant, name).
// It returns ErrSecretExists when the name already exists in the tenant — creation
// is distinct from rotation so a create never silently clobbers an existing secret
// (use RotateSecret to replace). Sealed must already be ciphertext. Tenant-scoped
// under RLS (AN-1).
func (s *Store) PutSecret(ctx context.Context, tenantID, name string, sealed []byte) (Secret, error) {
	var out Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO secret_store (tenant_id, name, sealed, version)
			 VALUES ($1, $2, $3, 1)
			 ON CONFLICT (tenant_id, name) DO NOTHING
			 RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantID, name, sealed).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		return insertSecretVersion(ctx, tx, tenantID, name, out.Version, sealed, out.UpdatedAt, nil)
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

// PutSecrets atomically imports multiple NEW sealed application secrets for a
// tenant. Each secret starts at version 1 and receives a matching history row in
// the same transaction. If any name already exists, no import rows are committed.
func (s *Store) PutSecrets(ctx context.Context, tenantID string, entries []SecretImportEntry) ([]Secret, error) {
	out := make([]Secret, 0, len(entries))
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, entry := range entries {
			var rec Secret
			if err := tx.QueryRow(ctx,
				`INSERT INTO secret_store (tenant_id, name, sealed, version)
				 VALUES ($1, $2, $3, 1)
				 ON CONFLICT (tenant_id, name) DO NOTHING
				 RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
				tenantID, entry.Name, entry.Sealed).
				Scan(&rec.ID, &rec.TenantID, &rec.Name, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
				return err
			}
			rec.Sealed = entry.Sealed
			if err := insertSecretVersion(ctx, tx, tenantID, rec.Name, rec.Version, rec.Sealed, rec.UpdatedAt, nil); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSecretExists
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

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
		if err := tx.QueryRow(ctx,
			`UPDATE secret_store
			    SET sealed = $3, version = version + 1, updated_at = now()
			  WHERE tenant_id = $1 AND name = $2
			  RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantID, name, sealed).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		return insertSecretVersion(ctx, tx, tenantID, name, out.Version, sealed, out.UpdatedAt, nil)
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

// GetSecretVersion loads one sealed historical version for (tenant, name, version).
// It returns ErrSecretNotFound when the tenant/name/version is absent. Tenant-scoped
// under RLS (AN-1).
func (s *Store) GetSecretVersion(ctx context.Context, tenantID, name string, version int) (SecretVersion, error) {
	var out SecretVersion
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var recovered sql.NullInt64
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, name, version, sealed, written_at, recovered_from_version
			   FROM secret_store_versions
			  WHERE tenant_id = $1 AND name = $2 AND version = $3`,
			tenantID, name, version).
			Scan(&out.TenantID, &out.Name, &out.Version, &out.Sealed, &out.WrittenAt, &recovered); err != nil {
			return err
		}
		if recovered.Valid {
			v := int(recovered.Int64)
			out.RecoveredFromVersion = &v
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretVersion{}, ErrSecretNotFound
	}
	return out, err
}

// RecoverSecretAt republishes the newest historical version written at or before at
// as the current value, creating a new monotonic version. It returns the new current
// row plus the historical source version used for recovery. Tenant-scoped under RLS
// (AN-1); plaintext never leaves the store.
func (s *Store) RecoverSecretAt(ctx context.Context, tenantID, name string, at time.Time) (Secret, SecretVersion, error) {
	var (
		out Secret
		src SecretVersion
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var recovered sql.NullInt64
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, name, version, sealed, written_at, recovered_from_version
			   FROM secret_store_versions
			  WHERE tenant_id = $1 AND name = $2 AND written_at <= $3
			  ORDER BY written_at DESC, version DESC
			  LIMIT 1`,
			tenantID, name, at.UTC()).
			Scan(&src.TenantID, &src.Name, &src.Version, &src.Sealed, &src.WrittenAt, &recovered); err != nil {
			return err
		}
		if recovered.Valid {
			v := int(recovered.Int64)
			src.RecoveredFromVersion = &v
		}
		if err := tx.QueryRow(ctx,
			`UPDATE secret_store
			    SET sealed = $3, version = version + 1, updated_at = now()
			  WHERE tenant_id = $1 AND name = $2
			  RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantID, name, src.Sealed).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		return insertSecretVersion(ctx, tx, tenantID, name, out.Version, src.Sealed, out.UpdatedAt, &src.Version)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Secret{}, SecretVersion{}, ErrSecretNotFound
	}
	if err != nil {
		return Secret{}, SecretVersion{}, err
	}
	out.Sealed = src.Sealed
	return out, src, nil
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
		_, err = tx.Exec(ctx,
			`DELETE FROM secret_store_versions WHERE tenant_id = $1 AND name = $2`,
			tenantID, name)
		return err
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

func insertSecretVersion(ctx context.Context, tx pgx.Tx, tenantID, name string, version int, sealed []byte, writtenAt time.Time, recoveredFromVersion *int) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at, recovered_from_version)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tenantID, name, version, sealed, writtenAt.UTC(), recoveredFromVersion)
	return err
}
