package store_test

import (
	"context"
	"sort"
	"testing"
)

// The two tests below derive the tenant-table set from the live PostgreSQL
// catalog (every base table in the public schema with a tenant_id column) rather
// than a hard-coded list, so a newly-added tenant table is automatically held to
// the same RLS invariants — a forgotten table cannot quietly escape the guard.

// TestEveryTenantTableForcesRLS is the ARCH-INFO-3 / TENANT-009 regression guard:
// the AN-1 isolation core is enforced at the storage layer by row-level security
// that is both ENABLED and FORCE-d on every tenant table. ENABLE alone is not
// enough — without FORCE, the table owner (which is the role the migrations and
// the projector connect as) BYPASSES RLS, so a query that forgot WithTenant would
// silently read across tenants. This test asserts, against the real migrated
// schema, that every table with a tenant_id column has relrowsecurity = true AND
// relforcerowsecurity = true. A new tenant table that enables but forgets to FORCE
// RLS (the classic AN-1 regression) fails here.
func TestEveryTenantTableForcesRLS(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	rows, err := s.Pool().Query(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relkind = 'r'
		  AND EXISTS (
		      SELECT 1 FROM pg_attribute a
		      WHERE a.attrelid = c.oid
		        AND a.attname = 'tenant_id'
		        AND a.attnum > 0
		        AND NOT a.attisdropped
		  )
		ORDER BY c.relname`)
	if err != nil {
		t.Fatalf("query tenant tables: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		var enabled, forced bool
		if err := rows.Scan(&name, &enabled, &forced); err != nil {
			t.Fatalf("scan: %v", err)
		}
		tables = append(tables, name)
		if !enabled {
			t.Errorf("tenant table %q does not ENABLE row-level security (AN-1)", name)
		}
		if !forced {
			t.Errorf("tenant table %q does not FORCE row-level security; the table owner would BYPASS RLS and a missing WithTenant would leak across tenants (AN-1, ARCH-INFO-3/TENANT-009)", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	// Guard against a vacuous pass: the platform has ~24 tenant tables; if the
	// catalog query suddenly returns almost nothing, the assertions above are
	// meaningless and the schema/discovery has drifted.
	if len(tables) < 20 {
		t.Fatalf("discovered only %d tenant tables (%v); expected ~24 — the RLS guard is not meaningful", len(tables), tables)
	}
	t.Logf("FORCE-d RLS verified on %d tenant tables: %v", len(tables), tables)
}

// TestNoTenantPolicyIsUsingOnly is the TENANT-008 regression guard: every RLS
// isolation policy on a tenant table must constrain WRITES as well as reads, i.e.
// it must carry a WITH CHECK clause, not only a USING clause. A USING-only policy
// is safe today (PostgreSQL re-uses USING as the implicit WITH CHECK), but it is
// inconsistent and a future-proofing hazard: broadening USING for reads would
// silently widen the write check too. After 0025 (tenants) and 0028 (credentials,
// certificate_profiles) the acceptance is that pg_policies shows ZERO USING-only
// policies on the tenant tables. This test fails if a new (or reverted) policy
// declares USING without WITH CHECK.
func TestNoTenantPolicyIsUsingOnly(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// pg_policies.qual is the USING expression; with_check is the WITH CHECK
	// expression. A policy that has a qual (a read filter) but a NULL with_check is
	// "USING-only". We restrict to policies on tables that carry tenant_id (the
	// tenant tables) so unrelated system policies are out of scope.
	rows, err := s.Pool().Query(ctx, `
		SELECT p.tablename, p.policyname
		FROM pg_policies p
		WHERE p.schemaname = 'public'
		  AND p.qual IS NOT NULL
		  AND p.with_check IS NULL
		  AND EXISTS (
		      SELECT 1
		      FROM pg_attribute a
		      JOIN pg_class c ON c.oid = a.attrelid
		      JOIN pg_namespace n ON n.oid = c.relnamespace
		      WHERE n.nspname = p.schemaname
		        AND c.relname = p.tablename
		        AND a.attname = 'tenant_id'
		        AND a.attnum > 0
		        AND NOT a.attisdropped
		  )
		ORDER BY p.tablename, p.policyname`)
	if err != nil {
		t.Fatalf("query USING-only policies: %v", err)
	}
	defer rows.Close()

	var usingOnly []string
	for rows.Next() {
		var table, policy string
		if err := rows.Scan(&table, &policy); err != nil {
			t.Fatalf("scan: %v", err)
		}
		usingOnly = append(usingOnly, table+"."+policy)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if len(usingOnly) != 0 {
		sort.Strings(usingOnly)
		t.Errorf("found %d USING-only RLS policies on tenant tables (must all carry WITH CHECK for AN-1 write symmetry, TENANT-008): %v", len(usingOnly), usingOnly)
	}
}
