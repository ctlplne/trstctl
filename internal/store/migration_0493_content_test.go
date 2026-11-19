// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0493KeepsHistoricalRotationReferenceAuthority(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 493)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "49300000-0000-4000-8000-000000000001"
	const scheduleID = "49300000-0000-4000-8000-000000000002"
	const oldReference = "fixture-retained-reference"
	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO secret_rotation_schedules
		    (tenant_id,id,name,provider,secret_key,old_ref,interval_seconds,next_run_at,created_at,updated_at)
	      VALUES ($1,$2,'fixture-schedule','fixture-provider','fixture/role',$3,60,now(),now(),now())`,
		tenant, scheduleID, oldReference)
	seed(`INSERT INTO dynamic_secret_leases
		    (tenant_id,id,tenant_epoch,idempotency_key,request_binding,provider,role,
		     backend_ref,sealed_credential,state,issue_outbox_id,revocation_status,
		     issued_at,expires_at,hard_expires_at,updated_at)
	      VALUES ($1,'fixture-lease','fixture-epoch','fixture-key','fixture-binding',
		      'fixture-provider','fixture/role',$2,'fixture-sealed'::bytea,'active',
		      4931,'none',now(),now()+interval '1 hour',now()+interval '2 hours',now())`,
		tenant, oldReference)
	const scheduleContent = `SELECT to_jsonb(s) - 'reference_provider_type' FROM secret_rotation_schedules s
		WHERE tenant_id = '49300000-0000-4000-8000-000000000001'`
	const leaseContent = `SELECT to_jsonb(l) - 'revocation_event_sequence' FROM dynamic_secret_leases l
		WHERE tenant_id = '49300000-0000-4000-8000-000000000001'`
	scheduleRows, scheduleDigest := checksumQuery(t, ctx, pool, scheduleContent)
	leaseRows, leaseDigest := checksumQuery(t, ctx, pool, leaseContent)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if count, digest := checksumQuery(t, ctx, pool, scheduleContent); count != 1 || count != scheduleRows || digest != scheduleDigest {
		t.Fatal("migration changed the retained schedule's original fields")
	}
	if count, digest := checksumQuery(t, ctx, pool, leaseContent); count != 1 || count != leaseRows || digest != leaseDigest {
		t.Fatal("migration changed the retained lease's original fields")
	}
	var priorType string
	var priorSequence uint64
	if err := pool.QueryRow(ctx, `SELECT reference_provider_type FROM secret_rotation_schedules
		WHERE tenant_id = $1 AND id = $2`, tenant, scheduleID).Scan(&priorType); err != nil || priorType != "" {
		t.Fatalf("migration attributed a provider type to an unproved legacy schedule: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT revocation_event_sequence FROM dynamic_secret_leases
		WHERE tenant_id = $1 AND id = 'fixture-lease'`, tenant).Scan(&priorSequence); err != nil || priorSequence != 0 {
		t.Fatalf("migration attributed a previous revocation to a lease without event evidence: %v", err)
	}
}
