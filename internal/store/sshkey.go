// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SSHKey is an inventoried SSH key's metadata (F42). It is keyed within a tenant
// by its fingerprint, so re-discovering the same key refreshes the existing row
// rather than duplicating it. StandingAccess marks a grant that confers
// persistent login; Orphaned marks an unattributable grant.
type SSHKey struct {
	ID             string
	TenantID       string
	Fingerprint    string // OpenSSH SHA256 fingerprint ("SHA256:<base64>")
	KeyType        string // ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ...
	Comment        string
	Source         string // discovery source kind
	Location       string // host:port or file path it was found at
	StandingAccess bool
	Orphaned       bool
	CreatedAt      time.Time
}

// UpsertSSHKey inserts or refreshes an SSH key by (tenant, fingerprint),
// returning it with its id and created_at. Tenant-scoped (RLS-enforced).
func (s *Store) UpsertSSHKey(ctx context.Context, k SSHKey) (SSHKey, error) {
	err := s.WithTenant(ctx, k.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO ssh_keys
			        (id, tenant_id, fingerprint, key_type, comment, source, location, standing_access, orphaned)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
			    SET key_type = EXCLUDED.key_type, comment = EXCLUDED.comment, source = EXCLUDED.source,
			        location = EXCLUDED.location, standing_access = EXCLUDED.standing_access,
			        orphaned = EXCLUDED.orphaned
			 RETURNING id::text, created_at`,
			k.TenantID, k.Fingerprint, k.KeyType, k.Comment, k.Source, k.Location, k.StandingAccess, k.Orphaned).
			Scan(&k.ID, &k.CreatedAt)
	})
	return k, err
}

// ListSSHKeysPage returns up to limit SSH keys with id greater than afterID
// (keyset pagination; pass ZeroUUID for the first page).
func (s *Store) ListSSHKeysPage(ctx context.Context, tenantID, afterID string, limit int) ([]SSHKey, error) {
	var out []SSHKey
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, fingerprint, key_type, comment, source, location,
			        standing_access, orphaned, created_at
			   FROM ssh_keys
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`,
			tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k SSHKey
			if err := rows.Scan(&k.ID, &k.TenantID, &k.Fingerprint, &k.KeyType, &k.Comment,
				&k.Source, &k.Location, &k.StandingAccess, &k.Orphaned, &k.CreatedAt); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}
