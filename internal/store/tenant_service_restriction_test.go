// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/tenancy"
)

// Seed persisted upgrade/restore state directly: core does not expose the
// commercial management operations that create these registry rows.
func TestCoreTenantServiceHonorsPersistedRestrictions(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	for _, id := range []string{tenantA, tenantB} {
		if err := s.RequireLiveTenantService(ctx, id); err != nil {
			t.Fatalf("ordinary core tenant refused: %v", err)
		}
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO provider_tenants
			(tenant_id,slug,name,status,created_at,updated_at) VALUES ($1,'core-restriction','Core restriction','active',now(),now())`, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "suspended", "offboarded", "offboarding", "offboard_failed", "unknown-future-state", ""} {
		t.Run(status, func(t *testing.T) {
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE provider_tenants SET status=$2 WHERE tenant_id=$1`, tenantA, status)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			err := s.RequireLiveTenantService(ctx, tenantA)
			if status == "active" {
				if err != nil {
					t.Fatalf("active customer refused: %v", err)
				}
			} else if !errors.Is(err, tenancy.ErrServiceUnavailable) {
				t.Fatalf("restricted customer admitted: %v", err)
			}
			if err := s.RequireLiveTenantService(ctx, tenantB); err != nil {
				t.Fatalf("another tenant affected: %v", err)
			}
			if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
				var rows int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM provider_tenants WHERE tenant_id=$1`, tenantA).Scan(&rows); err != nil {
					return err
				}
				if rows != 0 {
					t.Error("RLS exposed another customer's restriction")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
