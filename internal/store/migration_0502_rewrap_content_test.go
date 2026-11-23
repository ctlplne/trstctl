// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CR-045: migration 0502 adds comparison and admission schema without
// silently granting a legacy receipt an unverified v2 identity.
func TestMigration0502KeepsV1ReceiptsUnverifiedUntilAuthenticatedBackfill(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 502)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "49800000-0000-4000-8000-000000000001"
	const eventID = "49800000-0000-4000-8000-000000000002"
	if _, err := pool.Exec(ctx, `INSERT INTO application_secret_tenant_epochs (tenant_id,epoch_id)
		VALUES ($1,'49800000-0000-4000-8000-000000000003')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO application_secret_mutation_receipts
		(tenant_id,event_id,semantic_sha256,request_binding,secret_name,action,
		 result_version,result_created_at,result_updated_at,applied_at)
		VALUES ($1,$2,repeat('a',64),repeat('b',64),'legacy/v1','create',1,now(),now(),now())`,
		tenant, eventID); err != nil {
		t.Fatal(err)
	}
	const retained = `SELECT tenant_id,event_id,semantic_sha256,request_binding,
		secret_name,action,result_version,result_created_at,result_updated_at,applied_at
		FROM application_secret_mutation_receipts WHERE tenant_id='49800000-0000-4000-8000-000000000001'`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, retained)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, digest := checksumQuery(t, ctx, pool, retained); count != beforeCount || digest != beforeDigest {
		t.Fatal("migration changed an existing application-secret receipt")
	}
	var unverified bool
	if err := pool.QueryRow(ctx, `SELECT semantic_sha256_v2 IS NULL
		FROM application_secret_mutation_receipts WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID).
		Scan(&unverified); err != nil || !unverified {
		t.Fatalf("legacy receipt gained v2 without authentication: unverified=%t err=%v", unverified, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO application_secret_rewrap_gates
		(tenant_id,tenant_epoch,operation_id,operation_kind,rewrap_in_progress,v2_required)
		VALUES ($1,'49800000-0000-4000-8000-000000000003',
		        '49800000-0000-4000-8000-000000000004','migrate',true,true)`, tenant); err == nil {
		t.Fatal("migration gate accepted a still-unverified legacy receipt")
	}
}
