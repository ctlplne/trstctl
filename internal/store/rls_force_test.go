// SPDX-License-Identifier: MPL-2.0

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
// Both run through the SAME shared inventory helpers (store.TenantTableRLSStates,
// store.USINGOnlyTenantPolicies) that `trstctl doctor --prove-isolation` probes
// at runtime, so the CI guard and the field probe cannot drift apart.

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

	states, err := s.TenantTableRLSStates(ctx)
	if err != nil {
		t.Fatalf("query tenant tables: %v", err)
	}

	var tables []string
	for _, st := range states {
		tables = append(tables, st.Table)
		if !st.Enabled {
			t.Errorf("tenant table %q does not ENABLE row-level security (AN-1)", st.Table)
		}
		if !st.Forced {
			t.Errorf("tenant table %q does not FORCE row-level security; the table owner would BYPASS RLS and a missing WithTenant would leak across tenants (AN-1, ARCH-INFO-3/TENANT-009)", st.Table)
		}
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

	usingOnly, err := s.USINGOnlyTenantPolicies(ctx)
	if err != nil {
		t.Fatalf("query USING-only policies: %v", err)
	}
	if len(usingOnly) != 0 {
		sort.Strings(usingOnly)
		t.Errorf("found %d USING-only RLS policies on tenant tables (must all carry WITH CHECK for AN-1 write symmetry, TENANT-008): %v", len(usingOnly), usingOnly)
	}
}
