// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

// SCIMIdentity preserves provisioning identifiers separately from the authenticated
// principal. SubjectAttribute is an explicit trusted deployment mapping, never
// inferred from an email address or an arbitrary externalId.
type SCIMIdentity struct {
	UserName         string `json:"user_name"`
	ExternalID       string `json:"external_id,omitempty"`
	SubjectAttribute string `json:"subject_attribute"`
}

// TenantMember is a governed principal record for one tenant. It is a read model
// projected from tenant.member.* events, not a side table handlers mutate
// directly.
type TenantMember struct {
	SCIM           *SCIMIdentity
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
	if err := lockTenantMemberProjection(ctx, tx, m.TenantID, m.Subject); err != nil {
		return err
	}
	roles := m.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_members
		        (tenant_id, subject, subject_ref, display_name, email, roles, source, status, created_at, updated_at, scim_identity)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10)
		 ON CONFLICT (tenant_id, subject) DO UPDATE
		    SET subject_ref = EXCLUDED.subject_ref,
		        display_name = EXCLUDED.display_name,
		        email = EXCLUDED.email,
		        roles = EXCLUDED.roles,
		        source = EXCLUDED.source,
		        scim_identity = COALESCE(EXCLUDED.scim_identity, tenant_members.scim_identity),
		        status = 'active',
		        updated_at = EXCLUDED.updated_at,
		        offboarded_at = NULL,
		        offboarded_by = '',
		        offboard_reason = ''`,
		m.TenantID, m.Subject, privacy.SubjectRef(m.TenantID, m.Subject), m.DisplayName, m.Email, roles, m.Source, m.CreatedAt, m.UpdatedAt, m.SCIM)
	return err
}

// ApplyTenantMemberOffboardedTx projects a tenant.member.offboarded event. If
// the subject was never explicitly onboarded, it creates a tombstone so the audit
// and console still show that access for the subject was retired.
func (s *Store) ApplyTenantMemberOffboardedTx(ctx context.Context, tx pgx.Tx, m TenantMember) error {
	if err := lockTenantMemberProjection(ctx, tx, m.TenantID, m.Subject); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_members
		        (tenant_id, subject, subject_ref, display_name, email, roles, source, status,
		         created_at, updated_at, offboarded_at, offboarded_by, offboard_reason, scim_identity)
		 VALUES ($1, $2, $3, '', '', '{}', 'offboard', 'offboarded', $4, $4, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id, subject) DO UPDATE
		    SET subject_ref = EXCLUDED.subject_ref,
		        status = 'offboarded',
		        scim_identity = COALESCE(EXCLUDED.scim_identity, tenant_members.scim_identity),
		        updated_at = EXCLUDED.updated_at,
		        offboarded_at = COALESCE(tenant_members.offboarded_at, EXCLUDED.offboarded_at),
		        offboarded_by = CASE WHEN tenant_members.offboarded_by = '' THEN EXCLUDED.offboarded_by ELSE tenant_members.offboarded_by END,
		        offboard_reason = CASE WHEN tenant_members.offboard_reason = '' THEN EXCLUDED.offboard_reason ELSE tenant_members.offboard_reason END`,
		m.TenantID, m.Subject, privacy.SubjectRef(m.TenantID, m.Subject), m.UpdatedAt, m.OffboardedBy, m.OffboardReason, m.SCIM)
	return err
}

// GetTenantMember loads a member in the tenant context.
func (s *Store) GetTenantMember(ctx context.Context, tenantID, subject string) (TenantMember, error) {
	var m TenantMember
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, subject, display_name, email, roles, source, status,
			        created_at, updated_at, offboarded_at, offboarded_by, offboard_reason, scim_identity
			   FROM tenant_members WHERE tenant_id = $1 AND subject = $2`,
			tenantID, subject).Scan(&m.TenantID, &m.Subject, &m.DisplayName, &m.Email, &m.Roles, &m.Source, &m.Status, &m.CreatedAt, &m.UpdatedAt, &m.OffboardedAt, &m.OffboardedBy, &m.OffboardReason, &m.SCIM)
	})
	return m, err
}

// ListTenantMembersPage returns tenant members in subject order.
func (s *Store) ListTenantMembersPage(ctx context.Context, tenantID, afterSubject string, includeOffboarded bool, limit int) ([]TenantMember, error) {
	var out []TenantMember
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, subject, display_name, email, roles, source, status,
			        created_at, updated_at, offboarded_at, offboarded_by, offboard_reason, scim_identity
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
			if err := rows.Scan(&m.TenantID, &m.Subject, &m.DisplayName, &m.Email, &m.Roles, &m.Source, &m.Status, &m.CreatedAt, &m.UpdatedAt, &m.OffboardedAt, &m.OffboardedBy, &m.OffboardReason, &m.SCIM); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// ListTenantMembersByRole returns active tenant members carrying role. SCIM group
// membership maps onto this roles array, so the query stays tenant-filtered and
// bounded while the event log remains the source of truth for writes.
func (s *Store) ListTenantMembersByRole(ctx context.Context, tenantID, role string) ([]TenantMember, error) {
	var out []TenantMember
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, subject, display_name, email, roles, source, status,
			        created_at, updated_at, offboarded_at, offboarded_by, offboard_reason, scim_identity
			   FROM tenant_members
			  WHERE tenant_id = $1
			    AND status <> 'offboarded'
			    AND $2 = ANY(roles)
			  ORDER BY subject LIMIT 10000`,
			tenantID, role)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m TenantMember
			if err := rows.Scan(&m.TenantID, &m.Subject, &m.DisplayName, &m.Email, &m.Roles, &m.Source, &m.Status, &m.CreatedAt, &m.UpdatedAt, &m.OffboardedAt, &m.OffboardedBy, &m.OffboardReason, &m.SCIM); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// TenantMemberSCIMUserNameExists checks a provisioning alias before its event is
// appended. SCIM writers hold the cross-replica projection lock across this check
// and append; a database constraint independently protects the projection.
func (s *Store) TenantMemberSCIMUserNameExists(ctx context.Context, tenantID, userName, exceptSubject string) (bool, error) {
	var exists bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_members WHERE tenant_id = $1 AND subject <> $3 AND scim_identity IS NOT NULL AND lower(scim_identity->>'user_name') = lower($2))`, tenantID, userName, exceptSubject).Scan(&exists)
	})
	return exists, err
}

// Inline application and the durable event tail can project the same principal
// concurrently. Serialize their INSERTs on the primary-key identity so the SCIM
// username index cannot reject an identical speculative insert. Distinct
// principals still use the unique alias constraint to reject real collisions.
func lockTenantMemberProjection(ctx context.Context, tx pgx.Tx, tenantID, subject string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"tenant-member-projection\x1f"+tenantID+"\x1f"+subject)
	if err != nil {
		return fmt.Errorf("store: lock tenant member projection: %w", err)
	}
	return nil
}
