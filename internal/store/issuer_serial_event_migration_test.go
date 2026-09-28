// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0228PreservesMissingIssuerEventProvenance(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 228)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	if _, err := pool.Exec(ctx, `INSERT INTO ca_issued_certs (tenant_id,ca_id,serial,issued_at)
		VALUES($1,$2,'before-upgrade','2026-09-27T00:00:00Z')`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	// A rolled-back binary can still write the old column set. It must leave
	// the same explicit absence of proof as a row that preceded the migration.
	if _, err := pool.Exec(ctx, `INSERT INTO ca_issued_certs (tenant_id,ca_id,serial,issued_at)
		VALUES($1,$2,'older-writer','2026-09-27T00:00:00Z')`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	var missing int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ca_issued_certs WHERE tenant_id=$1
		AND issuance_event_id IS NULL AND issuance_event_type IS NULL
		AND issued_at='2026-09-27T00:00:00Z' AND revoked_at IS NULL`, tenantA).Scan(&missing); err != nil || missing != 2 {
		t.Fatalf("old serial evidence changed: rows=%d error=%v", missing, err)
	}
	for _, assignment := range []string{
		"issuance_event_id='event-only'",
		"issuance_event_type='ca.endentity.issued'",
		"issuance_event_id='',issuance_event_type='ca.endentity.issued'",
		"issuance_event_id='event',issuance_event_type='not.an.issuance'",
	} {
		if _, err := pool.Exec(ctx, `UPDATE ca_issued_certs SET `+assignment+` WHERE tenant_id=$1`, tenantA); err == nil {
			t.Fatalf("invalid source binding accepted: %s", assignment)
		}
	}
}
