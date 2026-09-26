// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0225PreservesOnlyKnownAgentRecipients(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 225)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const holder = "b9445160-dbc6-48fa-9c13-f078943486a9"
	if _, err := pool.Exec(ctx, `INSERT INTO outbox
	 (tenant_id,destination,payload,idempotency_key,claimed_by_agent_id,claim_attempts,claim_expires_at)
	 VALUES ($1,'endpoint.verify','{}','expired',$3,3,now()-interval '1 hour'),
	 ($1,'endpoint.verify','{}','reclaimed',NULL,4,NULL),
	 ($1,'endpoint.verify','{}','unclaimed',NULL,0,NULL),
	 ($2,'trust.distribute','{}','other-tenant',$3,1,now()+interval '1 hour')`, tenantA, tenantB, holder); err != nil {
		t.Fatal(err)
	}
	count, checksum := checksumQuery(t, ctx, pool, `SELECT to_jsonb(o)::text FROM outbox o ORDER BY id`)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if afterCount, afterChecksum := checksumQuery(t, ctx, pool, `SELECT to_jsonb(o)::text FROM outbox o ORDER BY id`); count != afterCount || checksum != afterChecksum {
		t.Fatal("migration changed live queue/lease state")
	}
	var bindings int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_job_attempt_bindings`).Scan(&bindings); err != nil || bindings != 2 {
		t.Fatalf("migration inferred unknown holders: count=%d err=%v", bindings, err)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		var actualTenant, agent, destination string
		var attempt int
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text,agent_id::text,destination,attempt FROM agent_job_attempt_bindings`).Scan(&actualTenant, &agent, &destination, &attempt); err != nil {
			t.Fatal(err)
		}
		expectedAttempt, expectedDestination := 3, "endpoint.verify"
		if tenant == tenantB {
			expectedAttempt, expectedDestination = 1, "trust.distribute"
		}
		if actualTenant != tenant || agent != holder || attempt != expectedAttempt || destination != expectedDestination {
			t.Fatalf("wrong authority binding: %s %s %d %s", actualTenant, agent, attempt, destination)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_job_attempt_bindings`).Scan(&bindings); err != nil || bindings != 1 {
			t.Fatalf("cross-tenant binding leak: count=%d err=%v", bindings, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var enabled, forced bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='agent_job_attempt_bindings'::regclass`).Scan(&enabled, &forced); err != nil || !enabled || !forced {
		t.Fatalf("claim bindings lack forced RLS: %v/%v %v", enabled, forced, err)
	}
}
