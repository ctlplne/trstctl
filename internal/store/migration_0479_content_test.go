// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// P1-L4: 0479 lets a delegated DNS-01 provider config name the CNAME target
// of its _validation-persist names. Configs from before it keep all their
// content and name none, so their standing records keep following the
// _acme-challenge delegation target.
func TestMigration0479KeepsDNS01ProviderConfigsWithNoPersistTarget(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 479)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "47900000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{
		`INSERT INTO acme_dns01_provider_configs
		(id, tenant_id, name, provider, zone, challenge_domain, delegation_target, credential_refs, config,
		 caa_issuer_domain, allowed_methods, allow_wildcards, allow_upstream_dv, created_at, updated_at)
		VALUES ('47900000-0000-4000-8000-0000000000a1', $1, 'delegated', 'webhook', 'p1l4.test', '',
		 'p1l4.auth.acme-dns.example.net', '{"bearer_token_ref":"secret://dns/p1l4"}', '{"endpoint":"https://dns.example.test"}',
		 'letsencrypt.org', '{dns-01}', true, true, '2026-11-13T00:00:00Z', '2026-11-13T00:00:00Z')`,
		`INSERT INTO acme_dns01_provider_configs
		(id, tenant_id, name, provider, zone, credential_refs, config, allowed_methods, created_at, updated_at)
		VALUES ('47900000-0000-4000-8000-0000000000a2', $1, 'direct', 'manual', 'direct.test', '{}', '{}',
		 '{dns-01,dns-persist-01}', '2026-11-12T00:00:00Z', '2026-11-12T00:00:00Z')`,
	} {
		if _, err := tx.Exec(ctx, seed, tenant); err != nil {
			t.Fatalf("seed a pre-0479 provider config: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const configs = `SELECT id::text, tenant_id::text, name, provider, zone, challenge_domain, delegation_target,
		credential_refs::text, config::text, caa_issuer_domain, allowed_methods, allow_wildcards, allow_upstream_dv,
		created_at, updated_at
		FROM acme_dns01_provider_configs ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, configs)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, configs); count != 2 || n != count || after != sum {
		t.Fatalf("0479 changed DNS-01 provider configs: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var named int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM acme_dns01_provider_configs WHERE persist_delegation_target <> ''`).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Fatalf("after 0479 %d configs name a persist delegation target; want none", named)
	}
}
