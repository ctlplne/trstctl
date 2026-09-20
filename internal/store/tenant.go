// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrTenantRegistrationConflict means a tenant UUID already names a different
// live registration. Registration is create-or-exact-replay; changing a live
// tenant requires a separate event, and reusing the UUID requires completed
// offboarding first.
var ErrTenantRegistrationConflict = errors.New("store: tenant UUID already has a different live registration")

// Tenant is the tenant read model (the Tenant entity).
type Tenant struct {
	TenantID  string
	Name      string
	CreatedAt time.Time
	EventSeq  uint64
}

// UpsertTenant inserts one tenant registration or accepts its exact replay. It is
// a legacy direct projection helper, so it takes the same exclusive lifecycle
// xact fence as live event registration before touching the row.
func (s *Store) UpsertTenant(ctx context.Context, t Tenant) error {
	if t.TenantID == "" {
		return fmt.Errorf("store: tenant registration requires a tenant id")
	}
	return s.WithTenantRegistrationFence(ctx, t.TenantID, func(tx pgx.Tx) error {
		return s.UpsertTenantTx(ctx, tx, t)
	})
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
		t.EventSeq = uint64(seq) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
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
	t.EventSeq = uint64(seq) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return t, err
}
