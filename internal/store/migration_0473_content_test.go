// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0473KeepsCertificatesWithNoEnrollmentPath: 0473 adds the
// enrollment path that issued a certificate (A244-L4). A certificate recorded
// before it keeps every value and reads an empty (unrecorded) path; the check
// admits a short lowercase path and refuses anything else; both metadata-order
// triggers cover the new column with the certificate's other facts.
func TestMigration0473KeepsCertificatesWithNoEnrollmentPath(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 473)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "47300000-0000-4000-8000-000000000001"
	withTenant := func(t *testing.T, statement string, args ...any) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := withTenant(t, `INSERT INTO certificates(id,tenant_id,subject,fingerprint,source,created_at,key_origin)
		VALUES('47300000-0000-4000-8000-0000000000c1',$1,'pre-473.example.test','pre-473','issued','2026-11-01T00:00:00Z','requester')`,
		tenant); err != nil {
		t.Fatalf("seed a pre-0473 certificate: %v", err)
	}
	const stable = `SELECT id::text,tenant_id::text,subject,fingerprint,source,created_at::text,status,key_origin,
		key_storage,key_exportable,key_generated_by,issuance_idempotency_key,issuing_external_ca_id
		FROM certificates ORDER BY tenant_id,id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0473 changed certificate content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var path string
	if err := pool.QueryRow(ctx, `SELECT enrollment_protocol FROM certificates`).Scan(&path); err != nil || path != "" {
		t.Fatalf("a pre-0473 certificate reads enrollment path %q (%v), want none recorded", path, err)
	}
	for _, bad := range []string{"ACME", "est scep", strings.Repeat("a", 33)} {
		if err := withTenant(t, `UPDATE certificates SET enrollment_protocol=$2 WHERE tenant_id=$1`, tenant, bad); err == nil {
			t.Fatalf("the check admitted enrollment path %q", bad)
		}
	}
	if err := withTenant(t, `UPDATE certificates SET enrollment_protocol='acme' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatalf("the check refused enrollment path acme: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger
		WHERE tgrelid='certificates'::regclass AND tgname IN ('certificate_metadata_order','certificate_metadata_statement_order')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	covered := 0
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(definition, "enrollment_protocol") || !strings.Contains(definition, "key_attestation") {
			t.Fatalf("trigger %s does not order the enrollment path with the other facts: %s", name, definition)
		}
		covered++
	}
	if covered != 2 {
		t.Fatalf("found %d metadata-order triggers, want 2", covered)
	}
}
