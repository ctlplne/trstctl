// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestIncidentListsUseStableNewestFirstCursorWithinTenant(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const issuer = "49100000-0000-4000-8000-000000000001"
	const identity = "49100000-0000-4000-8000-000000000002"
	ids := []string{
		"f9100000-0000-4000-8000-000000000003", // UUID order must not decide the latest run.
		"09100000-0000-4000-8000-000000000004",
		"09100000-0000-4000-8000-000000000005",
	}
	base := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for i, id := range ids {
		at := base.Add(time.Duration(i) * time.Hour)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO incident_fleet_reissuance_runs
			  (id, tenant_id, issuer_id, status, phase, created_at, updated_at)
			  VALUES ($1, $2, $3, 'executed', 'complete', $4, $4)`, id, tenantA, issuer, at); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO incident_executions
			  (id, tenant_id, compromised_identity_id, status, phase, created_at, updated_at)
			  VALUES ($1, $2, $3, 'executed', 'complete', $4, $4)`, id, tenantA, identity, at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Updating a run does not change its cursor position.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE incident_fleet_reissuance_runs SET updated_at = $3
		  WHERE tenant_id = $1 AND id = $2`, tenantA, ids[0], base.Add(4*time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		list  func(string, string, string, int) ([]string, error)
		scope string
	}{
		{name: "fleet", scope: issuer, list: func(tenant, scope, after string, limit int) ([]string, error) {
			rows, err := s.ListIncidentFleetReissuanceRunsPage(ctx, tenant, scope, after, limit)
			out := make([]string, 0, len(rows))
			for _, row := range rows {
				out = append(out, row.ID)
			}
			return out, err
		}},
		{name: "individual", scope: identity, list: func(tenant, scope, after string, limit int) ([]string, error) {
			rows, err := s.ListIncidentExecutionsPage(ctx, tenant, scope, after, limit)
			out := make([]string, 0, len(rows))
			for _, row := range rows {
				out = append(out, row.ID)
			}
			return out, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := tc.list(tenantA, tc.scope, "00000000-0000-0000-0000-000000000000", 2)
			if err != nil || len(first) != 2 || first[0] != ids[2] || first[1] != ids[1] {
				t.Fatalf("first page = %v, err=%v", first, err)
			}
			second, err := tc.list(tenantA, tc.scope, first[1], 2)
			if err != nil || len(second) != 1 || second[0] != ids[0] {
				t.Fatalf("second page = %v, err=%v", second, err)
			}
			other, err := tc.list(tenantB, tc.scope, "00000000-0000-0000-0000-000000000000", 2)
			if err != nil || len(other) != 0 {
				t.Fatalf("other tenant page = %v, err=%v", other, err)
			}
		})
	}
}
