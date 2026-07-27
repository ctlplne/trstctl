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

// ApplySSHKeyDiscoveredTx projects one immutable discovery finding into the
// tenant SSH inventory. The caller owns the projection transaction; this
// method never creates command-side state.
func (s *Store) ApplySSHKeyDiscoveredTx(ctx context.Context, tx pgx.Tx, k SSHKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO ssh_keys
		        (id, tenant_id, fingerprint, key_type, comment, source, location, standing_access, orphaned, created_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
		    SET key_type = EXCLUDED.key_type, comment = EXCLUDED.comment, source = EXCLUDED.source,
		        location = EXCLUDED.location, standing_access = EXCLUDED.standing_access,
		        orphaned = EXCLUDED.orphaned`,
		k.ID, k.TenantID, k.Fingerprint, k.KeyType, k.Comment, k.Source, k.Location,
		k.StandingAccess, k.Orphaned, k.CreatedAt)
	return err
}

// SSHFleetHost aggregates a host's discovered SSH key material. Every row in
// ssh_keys is a RAW key — a certificate issued by the SSH CA is not stored
// here — so a host appearing in this view has key-based access that does not
// go through the CA. That is the finding: standing keys are the access path
// certificate rotation cannot reach.
type SSHFleetHost struct {
	Location      string
	Keys          int
	StandingKeys  int
	OrphanedKeys  int
	KeyTypes      []string
	Sources       []string
	FirstObserved time.Time
	LastObserved  time.Time
}

// SSHFleetInventory groups the tenant's discovered SSH keys by host, worst
// first (most standing access, then most orphaned, then most keys), so the
// hosts that most need bringing under the CA sort to the top. limit bounds one
// read; 0 uses a sane default.
func (s *Store) SSHFleetInventory(ctx context.Context, tenantID string, limit int) ([]SSHFleetHost, error) {
	if limit <= 0 {
		limit = 200
	}
	var out []SSHFleetHost
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT COALESCE(NULLIF(location, ''), 'unattributed') AS host,
			        count(*)::integer AS keys,
			        count(*) FILTER (WHERE standing_access)::integer AS standing_keys,
			        count(*) FILTER (WHERE orphaned)::integer AS orphaned_keys,
			        array_agg(DISTINCT key_type) FILTER (WHERE key_type <> '') AS key_types,
			        array_agg(DISTINCT source) FILTER (WHERE source <> '') AS sources,
			        min(created_at) AS first_observed,
			        max(created_at) AS last_observed
			   FROM ssh_keys
			  WHERE tenant_id = $1
			  GROUP BY host
			  ORDER BY standing_keys DESC, orphaned_keys DESC, keys DESC, host
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var host SSHFleetHost
			if err := rows.Scan(&host.Location, &host.Keys, &host.StandingKeys, &host.OrphanedKeys,
				&host.KeyTypes, &host.Sources, &host.FirstObserved, &host.LastObserved); err != nil {
				return err
			}
			out = append(out, host)
		}
		return rows.Err()
	})
	return out, err
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
