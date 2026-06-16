package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestTenantsRLSWithCheckBlocksCrossTenantWrite is the ARCH-009 acceptance: the
// tenants_isolation policy must carry a WITH CHECK clause (not only USING), so a
// session bound to tenant A cannot INSERT or UPDATE a tenants row for tenant B
// under RLS. On the pre-fix tree (0001's USING-only policy) the cross-tenant INSERT
// SUCCEEDS — the write is never checked against the tenant GUC — so this test FAILS;
// after 0025 adds WITH CHECK it is denied and the test PASSES.
//
// It runs under WithTenant, which SET ROLEs to the non-superuser trstctl_app role
// (so FORCE-d RLS actually applies) and sets the trstctl.tenant_id GUC — exactly
// the path the product uses for tenant-scoped work.
func TestTenantsRLSWithCheckBlocksCrossTenantWrite(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Seed both tenants via the system pool (RLS-bypassing), as the projector does.
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}

	const tenantC = "33333333-3333-3333-3333-333333333333"

	// Under tenant A's RLS context, inserting a tenants row for a DIFFERENT tenant
	// (tenant C) must be denied by the policy's WITH CHECK clause.
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO tenants (tenant_id, name) VALUES ($1, $2)`, tenantC, "Sneaky")
		return err
	})
	if err == nil {
		t.Fatal("tenant A inserted a tenants row for another tenant; the WITH CHECK clause is missing (ARCH-009)")
	}
	if !isRLSViolation(err) {
		t.Fatalf("cross-tenant tenants INSERT failed with %v, want a row-level-security policy violation", err)
	}

	// The denied row must not exist (read via the system pool, cross-tenant).
	var n int
	if err := s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM tenants WHERE tenant_id = $1`, tenantC).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("the cross-tenant tenants row leaked in (%d rows); WITH CHECK did not block the write", n)
	}

	// Sanity: under tenant A's context, writing tenant A's OWN row (an UPDATE through
	// the policy) is permitted — the WITH CHECK constrains writes to the session's
	// tenant, it does not forbid all writes.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenants SET name = $2 WHERE tenant_id = $1`, tenantA, "Acme-renamed")
		return err
	}); err != nil {
		t.Fatalf("tenant A updating its own tenants row should be allowed, got %v", err)
	}
}

// isRLSViolation reports whether err is a PostgreSQL row-level-security policy
// violation (SQLSTATE 42501) or otherwise mentions the policy — either is the
// fail-closed denial we expect from the WITH CHECK clause.
func isRLSViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "row-level security") ||
		strings.Contains(msg, "row level security") ||
		strings.Contains(msg, "policy") ||
		strings.Contains(msg, "42501")
}
