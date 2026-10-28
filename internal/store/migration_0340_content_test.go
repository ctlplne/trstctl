// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A211: 0340 gives every revocation probe answer a scope and a CRL listing
// flag. An answer recorded before it keeps all its content and reads as the
// endpoint check it was, with no listing claimed.
func TestMigration0340KeepsRevocationAnswersAsEndpointChecks(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 340)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "34000000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO revocation_endpoint_health
		(tenant_id, target_key, protocol, endpoint, issuer_subject, certificate_id, certificate_subject,
		 certificate_fingerprint, certificate_serial, status, detail_code, signature_verified, revoked_count,
		 probe_id, bucket, batch_index, batch_count, observed_by_agent_id, observed_by_agent_name,
		 evidence_digest, observed_at)
		VALUES ($1, $2, 'crl', 'http://pki.example/a.crl', 'CN=Example CA', '34000000-0000-4000-8000-0000000000c1',
		 'CN=leaf.example', $3, '3a', 'fresh', 'ok', true, 4, '34000000-0000-4000-8000-0000000000d1',
		 '2026-10-28T00:00:00Z', 1, 1, '34000000-0000-4000-8000-0000000000e1', 'relay-1', $4,
		 '2026-10-28T00:05:00Z')`,
		tenant, strings.Repeat("ab", 32), strings.Repeat("cd", 32), strings.Repeat("ef", 32)); err != nil {
		t.Fatalf("seed a pre-0340 answer: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const stable = `SELECT tenant_id::text, target_key, protocol, endpoint, issuer_subject, certificate_id::text,
		certificate_subject, certificate_fingerprint, certificate_serial, status, detail_code, signature_verified,
		revoked_count, probe_id::text, bucket, batch_index, batch_count, observed_by_agent_id::text,
		observed_by_agent_name, evidence_digest, observed_at FROM revocation_endpoint_health ORDER BY target_key`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0340 changed revocation answers: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var scope string
	var listedNull bool
	if err := pool.QueryRow(ctx, `SELECT scope, certificate_listed IS NULL FROM revocation_endpoint_health`).
		Scan(&scope, &listedNull); err != nil {
		t.Fatal(err)
	}
	if scope != "endpoint" || !listedNull {
		t.Fatalf("an answer from before 0340 reads scope %q, listing null %v; want an endpoint check claiming no listing", scope, listedNull)
	}
}
