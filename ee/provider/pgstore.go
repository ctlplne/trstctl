// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

// Durable provider-plane registry (epic L3).
//
// The provider Store defaulted to MemStore, so a provider's customer list — the
// registry they run their business from — was lost on every deploy. This is the
// durable implementation, backed by the provider_tenants and
// provider_breakglass_grants tables (migration 0134).
//
// Reads and writes of the registry are CROSS-TENANT by nature — a provider
// lists all their customers — so they run through the store's system pool, the
// same RLS-bypassing path the core tenant registry uses. The one exception is
// DirectTenantSnapshot, which reads ONE customer's certificate inventory under
// THAT customer's RLS context (WithTenant), because a per-customer count is a
// per-tenant read and must be confined like any other.

// PGStore is the durable provider Store.
type PGStore struct {
	store *corestore.Store
}

// NewPGStore returns a durable provider registry over the core store.
func NewPGStore(s *corestore.Store) *PGStore {
	if s == nil {
		return nil
	}
	return &PGStore{store: s}
}

// RequireCustomerWorkQuiescent preserves remote claim evidence independently
// of the Provider edition. Call only while holding the customer service barrier.
func (p *PGStore) RequireCustomerWorkQuiescent(ctx context.Context, tenantID string) error {
	return p.store.RequireTenantAgentWorkQuiescent(ctx, tenantID)
}

var _ Store = (*PGStore)(nil)

// WithLifecycleMutation serializes rare Provider status commands with each
// other and boot catch-up across replicas. The existing dedicated lock
// pool keeps waiting commands from consuming projection/query connections.
// The caller rechecks authority and current status while holding the fence,
// then appends and projects the event before releasing it.
func (p *PGStore) WithLifecycleMutation(ctx context.Context, fn func(context.Context) error) error {
	return withAuthorityFence(ctx, p.store, fn)
}

func (p *PGStore) WithCustomerServiceBarrier(ctx context.Context, tenantID string, fn func(context.Context) error) error {
	return p.store.WithTenantServiceBarrier(ctx, tenantID, fn)
}

func (p *PGStore) CountBillableTenants(ctx context.Context) (int, error) {
	var n int
	err := p.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM provider_tenants WHERE status IN ('active','suspended','offboarding','offboard_failed')`).Scan(&n)
	return n, err
}

func (p *PGStore) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := p.store.SystemPool().Query(ctx,
		`SELECT tenant_id::text, slug, name, status, created_at, updated_at
		   FROM provider_tenants ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := scanProviderTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *PGStore) Tenant(ctx context.Context, id string) (Tenant, error) {
	row := p.store.SystemPool().QueryRow(ctx,
		`SELECT tenant_id::text, slug, name, status, created_at, updated_at
		   FROM provider_tenants WHERE tenant_id = $1`, id)
	t, err := scanProviderTenant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, err
}

// DirectTenantSnapshot reads ONE customer's certificate posture under that
// customer's RLS context — a per-tenant read, confined like any other. Health
// is derived from the tenant's registry status and its active-certificate
// count: a suspended tenant is degraded, an active tenant with certificates is
// healthy, and an active tenant with none is "no certificates" rather than
// silently healthy.
func (p *PGStore) DirectTenantSnapshot(ctx context.Context, tenantID string) (TenantSnapshot, error) {
	tenant, err := p.Tenant(ctx, tenantID)
	if err != nil {
		return TenantSnapshot{}, err
	}
	var active int
	if err := p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM certificates WHERE tenant_id = $1 AND status = 'active'`, tenantID).Scan(&active)
	}); err != nil {
		return TenantSnapshot{}, err
	}
	health := "healthy"
	switch {
	case tenant.Status == TenantSuspended:
		health = "suspended"
	case tenant.Status == TenantOffboarding:
		health = "offboarding"
	case tenant.Status == TenantOffboardFailed:
		health = "offboard_failed"
	case tenant.Status == TenantOffboarded:
		health = "offboarded"
	case active == 0:
		health = "no_certificates"
	}
	return TenantSnapshot{TenantID: tenantID, Health: health, ActiveCertificates: active}, nil
}

// TenantSnapshot is the break-glass telemetry reader twin. It deliberately
// shares the same tenant-confined implementation as the normal direct view.
func (p *PGStore) TenantSnapshot(ctx context.Context, tenantID string) (TenantSnapshot, error) {
	return p.DirectTenantSnapshot(ctx, tenantID)
}

func (p *PGStore) BreakGlassGrant(ctx context.Context, id string) (BreakGlassGrant, error) {
	row := p.store.SystemPool().QueryRow(ctx, breakGlassSelect+` WHERE id = $1`, id)
	g, err := scanBreakGlassGrant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return BreakGlassGrant{}, ErrNotFound
	}
	return g, err
}

const breakGlassSelect = `SELECT id, tenant_id::text, operator_id, operator_email, reason,
	requested_at, expires_at, consented_at, consented_by, denied_at, denied_by, revoked_at, use_count,
	consented_at_2, COALESCE(consented_by_2, '')
	FROM provider_breakglass_grants`

func scanProviderTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	var status string
	if err := row.Scan(&t.ID, &t.Slug, &t.Name, &status, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Tenant{}, err
	}
	t.Status = TenantStatus(status)
	return t, nil
}

func scanBreakGlassGrant(row pgx.Row) (BreakGlassGrant, error) {
	var g BreakGlassGrant
	var consentedAt, deniedAt, revokedAt, secondConsentedAt *time.Time
	if err := row.Scan(&g.ID, &g.TenantID, &g.OperatorID, &g.OperatorEmail, &g.Reason,
		&g.RequestedAt, &g.ExpiresAt, &consentedAt, &g.ConsentedBy, &deniedAt, &g.DeniedBy,
		&revokedAt, &g.UseCount, &secondConsentedAt, &g.SecondConsentedBy); err != nil {
		return BreakGlassGrant{}, err
	}
	if consentedAt != nil {
		g.ConsentedAt = *consentedAt
	}
	if secondConsentedAt != nil {
		g.SecondConsentedAt = *secondConsentedAt
	}
	if deniedAt != nil {
		g.DeniedAt = *deniedAt
	}
	if revokedAt != nil {
		g.RevokedAt = *revokedAt
	}
	return g, nil
}
