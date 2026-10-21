// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrVaultCubbyholeNotFound reports a missing cubbyhole entry for this token.
var ErrVaultCubbyholeNotFound = errors.New("store: cubbyhole entry not found")

// VaultCubbyholeEntry is one sealed per-token scratch value served by the
// Vault/OpenBao shim. Sealed is ciphertext only.
type VaultCubbyholeEntry struct {
	TenantID  string
	TokenHash string
	Path      string
	Sealed    []byte
	ExpiresAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PutVaultCubbyhole writes or replaces one entry of the token's cubbyhole.
func (s *Store) PutVaultCubbyhole(ctx context.Context, tenantID, tokenHash, path string, sealed []byte, expiresAt *time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO vault_cubbyhole (tenant_id, token_sha256, path, sealed, expires_at)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, token_sha256, path)
			 DO UPDATE SET sealed = EXCLUDED.sealed, expires_at = EXCLUDED.expires_at, updated_at = now()`,
			tenantID, tokenHash, path, sealed, expiresAt)
		return err
	})
}

// GetVaultCubbyhole reads one live entry of the token's cubbyhole.
func (s *Store) GetVaultCubbyhole(ctx context.Context, tenantID, tokenHash, path string, now time.Time) (VaultCubbyholeEntry, error) {
	var out VaultCubbyholeEntry
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, token_sha256, path, sealed, expires_at, created_at, updated_at
			   FROM vault_cubbyhole
			  WHERE tenant_id = $1 AND token_sha256 = $2 AND path = $3
			    AND (expires_at IS NULL OR expires_at > $4)`,
			tenantID, tokenHash, path, now.UTC()).
			Scan(&out.TenantID, &out.TokenHash, &out.Path, &out.Sealed, &out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return VaultCubbyholeEntry{}, ErrVaultCubbyholeNotFound
	}
	return out, err
}

// DeleteVaultCubbyhole removes one entry; a missing entry is not an error.
func (s *Store) DeleteVaultCubbyhole(ctx context.Context, tenantID, tokenHash, path string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM vault_cubbyhole WHERE tenant_id = $1 AND token_sha256 = $2 AND path = $3`,
			tenantID, tokenHash, path)
		return err
	})
}

// ListVaultCubbyhole returns the live entry paths of the token's cubbyhole
// under prefix (a folder prefix ends with "/"; "" lists everything).
func (s *Store) ListVaultCubbyhole(ctx context.Context, tenantID, tokenHash, prefix string, now time.Time) ([]string, error) {
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT path FROM vault_cubbyhole
			  WHERE tenant_id = $1 AND token_sha256 = $2 AND (expires_at IS NULL OR expires_at > $3)
			  ORDER BY path`,
			tenantID, tokenHash, now.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err != nil {
				return err
			}
			if strings.HasPrefix(path, prefix) {
				out = append(out, path)
			}
		}
		return rows.Err()
	})
	return out, err
}

// LookupSecretShare reads a share's metadata (never its sealed value) without
// consuming it, for the Vault shim's wrapping lookup. Expired shares report
// not found.
func (s *Store) LookupSecretShare(ctx context.Context, tenantID, tokenHash string, now time.Time) (SecretShare, error) {
	var out SecretShare
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, token_sha256, share_id, expires_at, created_at
			   FROM secret_shares WHERE tenant_id = $1 AND token_sha256 = $2 AND expires_at > $3`,
			tenantID, tokenHash, now.UTC()).
			Scan(&out.TenantID, &out.TokenHash, &out.ShareID, &out.ExpiresAt, &out.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretShare{}, ErrSecretShareNotFound
	}
	return out, err
}
