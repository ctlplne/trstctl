package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Tenant is the tenant read model (the Tenant entity).
type Tenant struct {
	TenantID  string
	Name      string
	CreatedAt time.Time
	EventSeq  uint64
}

// UpsertTenant inserts or updates a tenant row. It is a system (cross-tenant,
// RLS-bypassing) operation used by projection workers; it runs as the connecting
// role.
func (s *Store) UpsertTenant(ctx context.Context, t Tenant) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenants (tenant_id, name, event_seq) VALUES ($1, $2, $3)
		 ON CONFLICT (tenant_id) DO UPDATE SET name = EXCLUDED.name, event_seq = EXCLUDED.event_seq`,
		t.TenantID, t.Name, int64(t.EventSeq))
	return err
}

// ListTenants returns all tenants ordered by id. It is a system operation.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates the tenant registry (no tenant predicate); runs on the pool, not under RLS (AN-1 exemption).
		"SELECT tenant_id::text, name, created_at, event_seq FROM tenants ORDER BY tenant_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var (
			t   Tenant
			seq int64
		)
		if err := rows.Scan(&t.TenantID, &t.Name, &t.CreatedAt, &seq); err != nil {
			return nil, err
		}
		t.EventSeq = uint64(seq)
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTenant returns a tenant in its own tenant context (RLS-enforced). It exists
// to show tenant-scoped reads filter on tenant_id under RLS.
func (s *Store) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var (
		t   Tenant
		seq int64
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT tenant_id::text, name, created_at, event_seq FROM tenants WHERE tenant_id = $1",
			tenantID).Scan(&t.TenantID, &t.Name, &t.CreatedAt, &seq)
	})
	t.EventSeq = uint64(seq)
	return t, err
}
