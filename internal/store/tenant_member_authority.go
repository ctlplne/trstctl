// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// TenantMemberAdmission runs inside the command claim transaction after the
// subject lock. A refusal rolls the claim back before any event is appended.
type TenantMemberAdmission func(context.Context, pgx.Tx, string, string) error

// MemberAuthorityTx reads the target that the locked command would change.
func (s *Store) MemberAuthorityTx(ctx context.Context, tx pgx.Tx, tenantID, subject string) ([]string, string, bool, error) {
	var roles []string
	var status string
	err := tx.QueryRow(ctx, `SELECT roles, status FROM tenant_members
		WHERE tenant_id = $1 AND subject = $2`, tenantID, subject).Scan(&roles, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", false, nil
	}
	return roles, status, err == nil, err
}

// MemberCustomRolePermissionsTx resolves one current tenant role without
// opening another tenant transaction while a command lock is held.
func (s *Store) MemberCustomRolePermissionsTx(ctx context.Context, tx pgx.Tx, tenantID, name string) ([]string, error) {
	var permissions []string
	err := tx.QueryRow(ctx, `SELECT permissions FROM tenant_custom_roles
		WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL`, tenantID, name).Scan(&permissions)
	return permissions, err
}

// MemberWildcardHolderCountTx serializes authority removal across subjects.
// Pending offboards are excluded because their bearer grants are already fenced.
func (s *Store) MemberWildcardHolderCountTx(ctx context.Context, tx pgx.Tx, tenantID string, registeredWildcardRoles, registeredRoles []string) (int, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"member-wildcard-authority\x1f"+tenantID); err != nil {
		return 0, err
	}
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_members AS m
		WHERE m.tenant_id = $1 AND m.status = 'active'
		  AND (m.roles && $2::text[] OR EXISTS (
			SELECT 1 FROM tenant_custom_roles AS r
			WHERE r.tenant_id = m.tenant_id AND r.name = ANY(m.roles)
			  AND r.name <> ALL($3::text[])
			  AND r.deleted_at IS NULL AND '*' = ANY(r.permissions)))
		  AND NOT EXISTS (SELECT 1 FROM tenant_member_offboard_commands AS c
			WHERE c.tenant_id = m.tenant_id AND c.subject_ref = m.subject_ref
			  AND c.status = 'pending')
		  AND NOT EXISTS (SELECT 1 FROM tenant_member_upsert_commands AS c
			WHERE c.tenant_id = m.tenant_id AND c.subject_ref = m.subject_ref
			  AND c.status = 'pending')`, tenantID, registeredWildcardRoles, registeredRoles).Scan(&count)
	return count, err
}
