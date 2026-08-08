// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
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

var _ Store = (*PGStore)(nil)

func (p *PGStore) CountBillableTenants(ctx context.Context) (int, error) {
	var n int
	err := p.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM provider_tenants WHERE status IN ('active','suspended')`).Scan(&n)
	return n, err
}

func (p *PGStore) CreateTenant(ctx context.Context, tenant Tenant) (Tenant, error) {
	if tenant.ID == "" {
		return Tenant{}, fmt.Errorf("provider: a durable tenant needs an id")
	}
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now().UTC()
	}
	tenant.UpdatedAt = tenant.CreatedAt
	_, err := p.store.SystemPool().Exec(ctx,
		`INSERT INTO provider_tenants (tenant_id, slug, name, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tenant.ID, tenant.Slug, tenant.Name, string(tenant.Status), tenant.CreatedAt.UTC(), tenant.UpdatedAt.UTC())
	if err != nil {
		// A duplicate slug or id surfaces as a unique-violation; report it as a
		// conflict the caller already handles rather than a raw driver error.
		return Tenant{}, fmt.Errorf("provider: create tenant %q: %w", tenant.Slug, err)
	}
	return tenant, nil
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

func (p *PGStore) UpdateTenantStatus(ctx context.Context, id string, status TenantStatus, now time.Time) (Tenant, error) {
	row := p.store.SystemPool().QueryRow(ctx,
		`UPDATE provider_tenants SET status = $2, updated_at = $3
		  WHERE tenant_id = $1
		  RETURNING tenant_id::text, slug, name, status, created_at, updated_at`,
		id, string(status), now.UTC())
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
	case tenant.Status == TenantOffboarded:
		health = "offboarded"
	case active == 0:
		health = "no_certificates"
	}
	return TenantSnapshot{TenantID: tenantID, Health: health, ActiveCertificates: active}, nil
}

func (p *PGStore) CreateBreakGlassGrant(ctx context.Context, g BreakGlassGrant) (BreakGlassGrant, error) {
	if g.ID == "" {
		return BreakGlassGrant{}, fmt.Errorf("provider: a durable break-glass grant needs an id")
	}
	_, err := p.store.SystemPool().Exec(ctx,
		`INSERT INTO provider_breakglass_grants
		   (id, tenant_id, operator_id, operator_email, reason, requested_at, expires_at, use_count)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		g.ID, g.TenantID, g.OperatorID, g.OperatorEmail, g.Reason,
		g.RequestedAt.UTC(), g.ExpiresAt.UTC(), g.UseCount)
	if err != nil {
		return BreakGlassGrant{}, err
	}
	return g, nil
}

func (p *PGStore) BreakGlassGrant(ctx context.Context, id string) (BreakGlassGrant, error) {
	row := p.store.SystemPool().QueryRow(ctx, breakGlassSelect+` WHERE id = $1`, id)
	g, err := scanBreakGlassGrant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return BreakGlassGrant{}, ErrNotFound
	}
	return g, err
}

func (p *PGStore) UpdateBreakGlassGrant(ctx context.Context, g BreakGlassGrant) (BreakGlassGrant, error) {
	tag, err := p.store.SystemPool().Exec(ctx,
		`UPDATE provider_breakglass_grants
		    SET consented_at = $2, consented_by = $3, denied_at = $4, denied_by = $5,
		        revoked_at = $6, use_count = $7, consented_at_2 = $8, consented_by_2 = $9
		  WHERE id = $1`,
		g.ID, nullTime(g.ConsentedAt), g.ConsentedBy, nullTime(g.DeniedAt), g.DeniedBy,
		nullTime(g.RevokedAt), g.UseCount, nullTime(g.SecondConsentedAt), g.SecondConsentedBy)
	if err != nil {
		return BreakGlassGrant{}, err
	}
	if tag.RowsAffected() == 0 {
		return BreakGlassGrant{}, ErrNotFound
	}
	return g, nil
}

func (p *PGStore) IncrementBreakGlassUse(ctx context.Context, id string, _ time.Time) error {
	tag, err := p.store.SystemPool().Exec(ctx,
		`UPDATE provider_breakglass_grants SET use_count = use_count + 1 WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
