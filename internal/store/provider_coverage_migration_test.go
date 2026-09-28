// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0230PreservesLegacyObservationsWithoutInventingContinuity(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 230)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Hour)
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO provider_usage_coverage
			(tenant_id, observed_from, observed_to) VALUES ($1,$2,$3)`, tenant, from, to); err != nil {
			t.Fatal(err)
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	for _, tenant := range []string{tenantA, tenantB} {
		var gotFrom, gotTo time.Time
		var unknown bool
		if err := pool.QueryRow(ctx, `SELECT observed_from, observed_to, observed_ranges IS NULL
			FROM provider_usage_coverage WHERE tenant_id=$1`, tenant).Scan(&gotFrom, &gotTo, &unknown); err != nil {
			t.Fatal(err)
		}
		if !unknown || !gotFrom.Equal(from) || !gotTo.Equal(to) {
			t.Fatalf("legacy observations changed or were promoted to continuous proof: from=%s to=%s unknown=%t", gotFrom, gotTo, unknown)
		}
	}
	// Older backup rows omit the new column. PostgreSQL restores it as NULL,
	// preserving uncertainty without requiring guessed values during restore.
	var unknown bool
	if err := pool.QueryRow(ctx, `SELECT observed_ranges IS NULL FROM jsonb_populate_record(
		NULL::provider_usage_coverage, jsonb_build_object('tenant_id',$1::text,
		'observed_from',$2::timestamptz,'observed_to',$3::timestamptz))`, tenantA, from, to).Scan(&unknown); err != nil {
		t.Fatal(err)
	}
	if !unknown {
		t.Fatal("legacy backup invented continuity")
	}
}
