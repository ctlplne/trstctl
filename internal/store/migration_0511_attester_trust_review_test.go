// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/crypto"
)

// CR-195: an upgrade preserves the public configuration and pending command,
// but makes every old source ineligible until an issuer administrator reviews it.
func TestMigration0511FlagsHistoricalAttesterTrustAndKeepsCommandVersion(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 511)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "51100000-0000-4000-8000-000000000001"
	const source = "51100000-0000-4000-8000-000000000002"
	const event = "51100000-0000-4000-8000-000000000003"
	payload := []byte(`{"id":"51100000-0000-4000-8000-000000000002","enabled":true}`)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workload_attester_trust_sources
		(id,tenant_id,name,method,issuer,audience,jwks,created_at,updated_at,enabled)
		VALUES ($1,$2,'old-source','k8s_sat','https://kubernetes.default.svc','trstctl',
		'{"keys":[]}'::jsonb,now(),now(),true)`, source, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workload_attester_trust_commands
		(tenant_id,source_id,event_id,event_type,event_time,event_payload,payload_sha256,
		 binding_sha256,request_binding,target_disabled)
		VALUES ($1,$2,$3,'workload.attester_trust_source.upserted',now(),$4,$5,$6,$7,false)`,
		tenant, source, event, payload, crypto.SHA256Hex(payload), strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	var name, issuer string
	var enabled, review bool
	if err := pool.QueryRow(ctx, `SELECT name,issuer,enabled,admin_review_required
		FROM workload_attester_trust_sources WHERE tenant_id=$1 AND id=$2`, tenant, source).
		Scan(&name, &issuer, &enabled, &review); err != nil {
		t.Fatal(err)
	}
	if name != "old-source" || issuer != "https://kubernetes.default.svc" || !enabled || !review {
		t.Fatalf("migration changed public source or left it approved: name=%q issuer=%q enabled=%t review=%t",
			name, issuer, enabled, review)
	}
	var schemaVersion int
	if err := pool.QueryRow(ctx, `SELECT event_schema_version FROM workload_attester_trust_commands
		WHERE tenant_id=$1 AND source_id=$2`, tenant, source).Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != 1 {
		t.Fatalf("historical pending event schema version=%d, want 1", schemaVersion)
	}
}
