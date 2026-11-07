// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0428PreservesTargetsAndAdmitsWebConsoles is 0428's exact
// N-1 -> N case (A273): every registered target is unchanged and reads an
// empty web route, a webconsole target is admitted, an unknown type is still
// refused, and templates and sessions gain an empty web sign-in that must be
// a JSON object.
func TestMigration0428PreservesTargetsAndAdmitsWebConsoles(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 428)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "42800000-0000-4000-8000-000000000001"
	insert := func(kind string) error {
		_, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,$2,$2,'operator','2026-11-07T12:00:00Z')`, tenant, kind)
		return err
	}
	kinds := []string{"postgres", "ssh", "redis", "mysql", "mongodb", "clickhouse", "kubernetes", "snowflake", "aws", "gcp", "azure", "aws-console", "rdp", "windows_local", "netdevice", "account", "breakglass"}
	for _, kind := range kinds {
		if err := insert(kind); err != nil {
			t.Fatal(err)
		}
	}
	if err := insert("webconsole"); err == nil {
		t.Fatal("the pre-0428 schema admitted webconsole")
	}
	const before = `SELECT to_jsonb(t)::text FROM pam_targets t WHERE tenant_id='42800000-0000-4000-8000-000000000001' ORDER BY target_type,id`
	const after = `SELECT (to_jsonb(t) - 'web_route')::text FROM pam_targets t WHERE tenant_id='42800000-0000-4000-8000-000000000001' ORDER BY target_type,id`
	n, sum := checksumQuery(t, ctx, pool, before)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	m, afterSum := checksumQuery(t, ctx, pool, after)
	if n != len(kinds) || m != len(kinds) || sum != afterSum {
		t.Fatal("0428 changed previous tenant registrations")
	}
	var empty int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_targets WHERE tenant_id=$1 AND web_route='{}'::jsonb`, tenant).Scan(&empty); err != nil || empty != len(kinds) {
		t.Fatalf("previous targets read a web route: %d %v", empty, err)
	}
	if err := insert("webconsole"); err != nil {
		t.Fatalf("webconsole registration still rejected: %v", err)
	}
	if err := insert("unknown-target-type"); err == nil {
		t.Fatal("0428 admitted an unsupported target type")
	}
	if _, err := pool.Exec(ctx, `UPDATE pam_targets SET web_route='"not an object"'::jsonb WHERE tenant_id=$1 AND target_type='webconsole'`, tenant); err == nil {
		t.Fatal("a web route that is not an object was stored")
	}
	for _, table := range []string{"pam_access_templates", "pam_sessions"} {
		var def string
		if err := pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns WHERE table_name=$1 AND column_name='web_sign_in' AND is_nullable='NO'`, table).Scan(&def); err != nil || def != "'{}'::jsonb" {
			t.Fatalf("%s.web_sign_in: default %q, %v", table, def, err)
		}
	}
}
