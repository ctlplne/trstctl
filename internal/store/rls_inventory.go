// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
)

// The two catalog inventories below are THE canonical AN-1 posture queries,
// shared by the CI guards (TestEveryTenantTableForcesRLS,
// TestNoTenantPolicyIsUsingOnly) and by `trstctl doctor --prove-isolation`, so
// the test and the field probe can never drift: both derive the tenant-table
// set from pg_catalog (every base public table carrying a tenant_id column),
// never from a hand-typed list.

// TenantTableRLS is one tenant table's row-level-security posture.
type TenantTableRLS struct {
	Table   string
	Enabled bool
	Forced  bool
}

// TenantTableRLSStates inventories every tenant table's RLS posture from the
// live catalog. AN-1 requires Enabled AND Forced on every row: ENABLE alone
// lets the table owner bypass RLS, so a query that forgot WithTenant would
// silently read across tenants.
func (s *Store) TenantTableRLSStates(ctx context.Context) ([]TenantTableRLS, error) {
	//trstctl:system-query — cross-tenant by design: reads only pg_catalog metadata (table names and RLS flags), never tenant rows, to prove the RLS posture itself; the CI guard and doctor's ISO-1 probe share this inventory so they cannot drift.
	rows, err := s.SystemPool().Query(ctx, `
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
		return nil, err
	}
	defer rows.Close()
	var out []TenantTableRLS
	for rows.Next() {
		var t TenantTableRLS
		if err := rows.Scan(&t.Table, &t.Enabled, &t.Forced); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DoctorProbeResidue counts leftover rows under doctor's reserved synthetic
// probe-tenant prefix in the two tables the isolation probes write (agents,
// ca_authorities). Doctor calls it before probing (a leftover from a prior run
// is a FAIL) and after cleanup (any residue is a FAIL) — a leaked probe tenant
// must never linger silently in an operator's audit surface.
func (s *Store) DoctorProbeResidue(ctx context.Context, tenantPrefix string) (int, error) {
	//trstctl:system-query — cross-tenant by design: doctor's leak sweep matches only the reserved synthetic probe-tenant id prefix, so real tenant rows are structurally outside the predicate; RLS stays intact for every real tenant.
	row := s.SystemPool().QueryRow(ctx, `
		SELECT (SELECT count(*) FROM agents         WHERE tenant_id::text LIKE $1 || '%')
		     + (SELECT count(*) FROM ca_authorities WHERE tenant_id::text LIKE $1 || '%')`,
		tenantPrefix)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// USINGOnlyTenantPolicies lists the RLS policies on tenant tables that carry a
// USING clause but no WITH CHECK — the TENANT-008 hazard: safe today because
// PostgreSQL reuses USING as the implicit write check, but a broadened read
// filter would silently widen writes too. AN-1 wants this list empty.
func (s *Store) USINGOnlyTenantPolicies(ctx context.Context) ([]string, error) {
	//trstctl:system-query — cross-tenant by design: reads only pg_policies/pg_catalog metadata (policy names and clause presence), never tenant rows, to prove the RLS write-check posture; shared verbatim by the TENANT-008 CI guard and doctor's ISO-2 probe.
	rows, err := s.SystemPool().Query(ctx, `
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
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var table, policy string
		if err := rows.Scan(&table, &policy); err != nil {
			return nil, err
		}
		out = append(out, table+"."+policy)
	}
	return out, rows.Err()
}
