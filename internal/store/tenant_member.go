package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// TenantMember is a governed principal record for one tenant. It is a read model
// projected from tenant.member.* events, not a side table handlers mutate
// directly.
type TenantMember struct {
	TenantID       string
	Subject        string
	DisplayName    string
	Email          string
	Roles          []string
	Source         string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	OffboardedAt   *time.Time
	OffboardedBy   string
	OffboardReason string
}

// ApplyTenantMemberUpsertedTx projects a tenant.member.upserted event.
func (s *Store) ApplyTenantMemberUpsertedTx(ctx context.Context, tx pgx.Tx, m TenantMember) error {
	roles := m.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_members
		        (tenant_id, subject, display_name, email, roles, source, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8)
		 ON CONFLICT (tenant_id, subject) DO UPDATE
		    SET display_name = EXCLUDED.display_name,
		        email = EXCLUDED.email,
		        roles = EXCLUDED.roles,
		        source = EXCLUDED.source,
		        status = 'active',
		        updated_at = EXCLUDED.updated_at,
		        offboarded_at = NULL,
		        offboarded_by = '',
		        offboard_reason = ''`,
		m.TenantID, m.Subject, m.DisplayName, m.Email, roles, m.Source, m.CreatedAt, m.UpdatedAt)
	return err
}

// ApplyTenantMemberOffboardedTx projects a tenant.member.offboarded event. If
// the subject was never explicitly onboarded, it creates a tombstone so the audit
// and console still show that access for the subject was retired.
func (s *Store) ApplyTenantMemberOffboardedTx(ctx context.Context, tx pgx.Tx, m TenantMember) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_members
		        (tenant_id, subject, display_name, email, roles, source, status,
		         created_at, updated_at, offboarded_at, offboarded_by, offboard_reason)
		 VALUES ($1, $2, '', '', '{}', 'offboard', 'offboarded', $3, $3, $3, $4, $5)
		 ON CONFLICT (tenant_id, subject) DO UPDATE
		    SET status = 'offboarded',
		        updated_at = EXCLUDED.updated_at,
		        offboarded_at = COALESCE(tenant_members.offboarded_at, EXCLUDED.offboarded_at),
		        offboarded_by = CASE WHEN tenant_members.offboarded_by = '' THEN EXCLUDED.offboarded_by ELSE tenant_members.offboarded_by END,
		        offboard_reason = CASE WHEN tenant_members.offboard_reason = '' THEN EXCLUDED.offboard_reason ELSE tenant_members.offboard_reason END`,
		m.TenantID, m.Subject, m.UpdatedAt, m.OffboardedBy, m.OffboardReason)
	return err
}

// GetTenantMember loads a member in the tenant context.
func (s *Store) GetTenantMember(ctx context.Context, tenantID, subject string) (TenantMember, error) {
	var m TenantMember
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, subject, display_name, email, roles, source, status,
			        created_at, updated_at, offboarded_at, offboarded_by, offboard_reason
			   FROM tenant_members WHERE tenant_id = $1 AND subject = $2`,
			tenantID, subject).Scan(&m.TenantID, &m.Subject, &m.DisplayName, &m.Email, &m.Roles, &m.Source, &m.Status, &m.CreatedAt, &m.UpdatedAt, &m.OffboardedAt, &m.OffboardedBy, &m.OffboardReason)
	})
	return m, err
}

// ListTenantMembersPage returns tenant members in subject order.
func (s *Store) ListTenantMembersPage(ctx context.Context, tenantID, afterSubject string, includeOffboarded bool, limit int) ([]TenantMember, error) {
	var out []TenantMember
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, subject, display_name, email, roles, source, status,
			        created_at, updated_at, offboarded_at, offboarded_by, offboard_reason
			   FROM tenant_members
			  WHERE tenant_id = $1
			    AND subject > $2
			    AND ($3 OR status <> 'offboarded')
			  ORDER BY subject LIMIT $4`,
			tenantID, afterSubject, includeOffboarded, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m TenantMember
			if err := rows.Scan(&m.TenantID, &m.Subject, &m.DisplayName, &m.Email, &m.Roles, &m.Source, &m.Status, &m.CreatedAt, &m.UpdatedAt, &m.OffboardedAt, &m.OffboardedBy, &m.OffboardReason); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}
