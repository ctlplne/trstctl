// SPDX-License-Identifier: LicenseRef-trstctl-EE

package silo

import (
	"context"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// Durable silo placement (epic L4).
//
// The in-memory registry lost every tenant's isolation model on restart,
// SILENTLY: a customer who bought hard isolation had it until the first deploy,
// and nothing running would have said otherwise. For a sovereignty feature that
// is the whole product failing quietly.
type PGRegistry struct {
	store *corestore.Store
}

// NewPGRegistry builds the durable registry.
func NewPGRegistry(s *corestore.Store) *PGRegistry { return &PGRegistry{store: s} }

var _ Registry = (*PGRegistry)(nil)

// Snapshot reads every tenant's placement.
//
// Cross-tenant by necessity — the router needs the whole map to route anything —
// so it runs on the system pool with the marker the RLS-bypass inventory guard
// requires.
func (p *PGRegistry) Snapshot(ctx context.Context) (map[string]Tenant, error) {
	out := map[string]Tenant{}
	if p == nil || p.store == nil {
		// A nil store yields an EMPTY map, not an error. The router reads empty
		// as "everything is on the shared default", which is the safe reading:
		// it never invents an isolation guarantee nothing is backing.
		return out, nil
	}
	rows, err := p.store.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the silo router must hold every tenant's placement to route any of them, and a per-tenant read cannot produce a routing table (AN-1 exemption).
		`SELECT tenant_id::text, slug, isolation_model, status FROM tenant_silos`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t Tenant
		var model string
		if err := rows.Scan(&t.ID, &t.Slug, &model, &t.Status); err != nil {
			return nil, err
		}
		// An unset model is the SHARED default, never an upgrade. Guessing
		// upward would hand a tenant an isolation guarantee nobody sold them
		// and nobody is providing.
		t.Model = tenancy.IsolationModel(model)
		out[t.ID] = t
	}
	return out, rows.Err()
}

// Place records a tenant's silo and residency zone.
func (p *PGRegistry) Place(ctx context.Context, tenantID, slug, model, zone, status string) error {
	if p == nil || p.store == nil {
		return nil
	}
	return p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO tenant_silos (tenant_id, slug, isolation_model, residency_zone, status)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   slug = EXCLUDED.slug, isolation_model = EXCLUDED.isolation_model,
			   residency_zone = EXCLUDED.residency_zone, status = EXCLUDED.status,
			   updated_at = now()`,
			tenantID, slug, model, zone, status)
		return err
	})
}

// ResidencyZone reports where a tenant's data is pinned.
//
// An empty zone means UNPINNED, and a caller must not read that as "compliant
// with whatever zone was asked about". An absent pin is the absence of a
// guarantee, not a permissive one.
func (p *PGRegistry) ResidencyZone(ctx context.Context, tenantID string) (string, error) {
	if p == nil || p.store == nil {
		return "", nil
	}
	var zone string
	err := p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT residency_zone FROM tenant_silos WHERE tenant_id = $1`, tenantID).Scan(&zone)
	})
	if err != nil {
		return "", nil
	}
	return zone, nil
}
