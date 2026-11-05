// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// An upgrade must not attach rules to an old template/session or change any
// previous column. Both authority-bearing defaults are empty, not permissive
// stand-ins for a policy that was never reviewed.
func TestMigration0405AddsNoCommandPolicyToLegacyAccess(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 405)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "40500000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_access_templates(tenant_id,id,name,reason,required_approvals,max_ttl_seconds,revision,saved_by,saved_at)
 VALUES($1,'40500000-0000-4000-8000-000000000002','maintenance','Planned change',2,900,3,'operator','2026-11-05T01:00:00Z')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_sessions(tenant_id,id,target_type,target_id,role,status,subject,requested_by,started_at,expires_at)
 VALUES($1,'40500000-0000-4000-8000-000000000003','postgres','orders','readonly','active','operator','operator','2026-11-05T01:00:00Z','2026-11-05T02:00:00Z')`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	queries := []string{
		`SELECT (to_jsonb(t)-'command_rules')::text FROM pam_access_templates t WHERE tenant_id='40500000-0000-4000-8000-000000000001' ORDER BY id`,
		`SELECT (to_jsonb(t)-'command_policy')::text FROM pam_sessions t WHERE tenant_id='40500000-0000-4000-8000-000000000001' ORDER BY id`,
	}
	type content struct {
		count int
		sum   string
	}
	before := make([]content, len(queries))
	for i, q := range queries {
		before[i].count, before[i].sum = checksumQuery(t, ctx, pool, q)
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	for i, q := range queries {
		n, sum := checksumQuery(t, ctx, pool, q)
		if before[i].count != 1 || n != 1 || sum != before[i].sum {
			t.Fatalf("0405 changed previous access data for query%d: %d/%s -> %d/%s", i, before[i].count, before[i].sum, n, sum)
		}
	}
	var rules, policy string
	if err := pool.QueryRow(ctx, `SELECT command_rules::text FROM pam_access_templates WHERE tenant_id=$1`, tenant).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT command_policy::text FROM pam_sessions WHERE tenant_id=$1`, tenant).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	if rules != "[]" || policy != "{}" {
		t.Fatalf("legacy rows gained policy: rules=%s policy=%s", rules, policy)
	}
	var actions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_command_actions WHERE tenant_id=$1`, tenant).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if actions != 0 {
		t.Fatal("migration invented a command decision")
	}
}
