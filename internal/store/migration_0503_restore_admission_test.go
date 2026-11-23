// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0503RestoreMarkerIsTargetLocalAndOwnerOnly(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 503)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	for _, table := range []string{
		"trstctl_recovery.restore_markers", "trstctl_recovery.restore_activity_tokens",
		"trstctl_recovery.event_ingress_journal", // CR-045 producer/wire commitment survives broker ACK and SQL rollback
	} {
		var enabled, forced, appInsert bool
		if err := pool.QueryRow(ctx, `SELECT c.relrowsecurity,c.relforcerowsecurity,
			has_table_privilege('trstctl_app',$1,'INSERT') FROM pg_class AS c
			WHERE c.oid=$1::regclass`, table).Scan(&enabled, &forced, &appInsert); err != nil {
			t.Fatal(err)
		}
		if !enabled || !forced || appInsert {
			t.Fatalf("%s RLS enabled=%t forced=%t app insert=%t; want forced RLS and owner-only writes", table, enabled, forced, appInsert)
		}
	}
	const control = "00000000-0000-0000-0000-000000000004"
	const tenant = "49900000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO trstctl_recovery.restore_markers
		(tenant_id,operation_id,artifact_sha256,event_cut,deployment_id,phase)
		VALUES ($1,'49900000-0000-4000-8000-000000000002',repeat('a',64),9,'target-a','prepared')`, tenant); err == nil {
		t.Fatal("restore marker accepted a customer tenant as the deployment-control partition")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO trstctl_recovery.restore_markers
		(tenant_id,operation_id,artifact_sha256,event_cut,deployment_id,phase)
		VALUES ($1,'49900000-0000-4000-8000-000000000002',repeat('a',64),9,'target-a','prepared')`, control); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (tenant_id,name,event_seq) VALUES ($1,'reserved',1)`, control); err == nil {
		t.Fatal("tenant registration accepted the reserved restore-control partition")
	}
}
