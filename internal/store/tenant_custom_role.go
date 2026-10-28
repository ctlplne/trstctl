// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// TenantCustomRole is a role a tenant defined as a named subset of the core
// permission vocabulary (A207). Members hold it by name, like a built-in role.
type TenantCustomRole struct {
	TenantID      string
	Name          string
	Description   string
	Permissions   []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	EventSequence uint64
}

// ApplyTenantCustomRoleUpsertedTx projects access.role.upserted. A later
// definition replaces an earlier one, a defined-again role leaves its
// tombstone, and a replay of this or an earlier event changes nothing.
func (s *Store) ApplyTenantCustomRoleUpsertedTx(ctx context.Context, tx pgx.Tx, role TenantCustomRole) error {
	permissions := role.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_custom_roles (tenant_id, name, description, permissions, created_at, updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $5, $6)
		 ON CONFLICT (tenant_id, name) DO UPDATE
		    SET description = EXCLUDED.description, permissions = EXCLUDED.permissions,
		        created_at = CASE WHEN tenant_custom_roles.deleted_at IS NULL THEN tenant_custom_roles.created_at ELSE EXCLUDED.created_at END,
		        updated_at = EXCLUDED.updated_at, deleted_at = NULL, event_sequence = EXCLUDED.event_sequence
		  WHERE tenant_custom_roles.event_sequence < EXCLUDED.event_sequence`,
		role.TenantID, role.Name, role.Description, permissions, role.UpdatedAt,
		int64(role.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// ApplyTenantCustomRoleDeletedTx projects access.role.deleted as a tombstone.
func (s *Store) ApplyTenantCustomRoleDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, name string, at time.Time, sequence uint64) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_custom_roles (tenant_id, name, created_at, updated_at, deleted_at, event_sequence)
		 VALUES ($1, $2, $3, $3, $3, $4)
		 ON CONFLICT (tenant_id, name) DO UPDATE
		    SET permissions = '{}'::text[], updated_at = EXCLUDED.updated_at, deleted_at = EXCLUDED.deleted_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE tenant_custom_roles.event_sequence < EXCLUDED.event_sequence`,
		tenantID, name, at, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

const tenantCustomRoleColumns = `tenant_id::text, name, description, permissions, created_at, updated_at, event_sequence`

func scanTenantCustomRole(row pgx.Row, role *TenantCustomRole) error {
	var seq int64
	if err := row.Scan(&role.TenantID, &role.Name, &role.Description, &role.Permissions,
		&role.CreatedAt, &role.UpdatedAt, &seq); err != nil {
		return err
	}
	role.EventSequence = uint64(seq) // #nosec G115 -- positive by constraint (CWE-190)
	return nil
}

// GetTenantCustomRole returns one defined (not deleted) custom role.
func (s *Store) GetTenantCustomRole(ctx context.Context, tenantID, name string) (TenantCustomRole, error) {
	var role TenantCustomRole
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanTenantCustomRole(tx.QueryRow(ctx,
			`SELECT `+tenantCustomRoleColumns+` FROM tenant_custom_roles
			  WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL`, tenantID, name), &role)
	})
	return role, err
}

// ListTenantCustomRoles returns the tenant's defined custom roles by name. With
// names, only those roles; it is the per-request read that resolves a
// principal's custom roles, so a changed or deleted role applies to the next
// request on every replica.
func (s *Store) ListTenantCustomRoles(ctx context.Context, tenantID string, names ...string) ([]TenantCustomRole, error) {
	var out []TenantCustomRole
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+tenantCustomRoleColumns+` FROM tenant_custom_roles
			  WHERE tenant_id = $1 AND deleted_at IS NULL AND (coalesce(cardinality($2::text[]), 0) = 0 OR name = ANY($2::text[]))
			  ORDER BY name`, tenantID, names)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var role TenantCustomRole
			if err := scanTenantCustomRole(rows, &role); err != nil {
				return err
			}
			out = append(out, role)
		}
		return rows.Err()
	})
	return out, err
}

// TenantCustomRoleHolders counts the tenant's members that hold the role; a
// held role cannot be deleted.
func (s *Store) TenantCustomRoleHolders(ctx context.Context, tenantID, name string) (int, error) {
	var n int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND $2 = ANY(roles) AND status <> 'offboarded'`,
			tenantID, name).Scan(&n)
	})
	return n, err
}
