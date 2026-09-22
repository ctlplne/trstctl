// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0222PreservesUnknownCertificateIdentity(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 222)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	for tenantIndex, tenant := range []string{tenantA, tenantB} {
		for kindIndex, kind := range []string{"certificate-key", "tls-endpoint"} {
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", tenantIndex*2+kindIndex+1)
			if _, err := pool.Exec(ctx, `INSERT INTO crypto_assets
			 (id,tenant_id,signature,kind,location,algorithm,key_bits,reasons,event_sequence,is_active,created_at)
			 VALUES ($1,$2,$3,$3,'shared.example.test:443','ECDSA',256,ARRAY['retained observation'],17,false,'2026-09-01T00:00:00Z')`,
				id, tenant, kind); err != nil {
				t.Fatalf("seed historical %s/%s: %v", tenant, kind, err)
			}
		}
	}
	const beforeQuery = `SELECT tenant_id::text,id::text,to_jsonb(a)::text FROM crypto_assets a
	 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`
	const afterQuery = `SELECT tenant_id::text,id::text,(to_jsonb(a)-'certificate_fingerprint')::text FROM crypto_assets a
	 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`
	count, checksum := checksumQuery(t, ctx, pool, beforeQuery)
	if count != 4 {
		t.Fatalf("need populated observations from both tenants, got %d", count)
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if gotCount, gotChecksum := checksumQuery(t, ctx, pool, afterQuery); gotCount != count || gotChecksum != checksum {
		t.Fatalf("0222 changed retained observations: before %d/%s, after %d/%s", count, checksum, gotCount, gotChecksum)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		var invented int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM crypto_assets
		 WHERE tenant_id=$1 AND certificate_fingerprint IS DISTINCT FROM ''`, tenant).Scan(&invented); err != nil || invented != 0 {
			t.Fatalf("historical identity must remain unknown for %s: invented=%d err=%v", tenant, invented, err)
		}
	}
	constraintValidated := func(want bool) {
		t.Helper()
		var got bool
		if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint
		 WHERE conrelid='crypto_assets'::regclass AND conname='crypto_assets_certificate_fingerprint_valid'`).Scan(&got); err != nil || got != want {
			t.Fatalf("constraint validated=%v, want %v: %v", got, want, err)
		}
	}
	constraintValidated(false)
	for _, invalid := range []struct {
		kind, state string
		value       any
	}{
		{"certificate-key", "23514", strings.Repeat("A", 64)},
		{"certificate-key", "23514", strings.Repeat("g", 64)},
		{"certificate-key", "23514", "abc"},
		{"certificate-key", "23502", nil},
		{"tls-endpoint", "23514", strings.Repeat("a", 64)},
	} {
		_, err := pool.Exec(ctx, `UPDATE crypto_assets SET certificate_fingerprint=$3 WHERE tenant_id=$1 AND kind=$2`, tenantA, invalid.kind, invalid.value)
		var constraintError *pgconn.PgError
		if !errors.As(err, &constraintError) || constraintError.Code != invalid.state {
			t.Fatalf("invalid %s fingerprint must fail with %s, got %v", invalid.kind, invalid.state, err)
		}
	}
	for index, tenant := range []string{tenantA, tenantB} {
		fingerprint := strings.Repeat([]string{"a", "b"}[index], 64)
		if _, err := pool.Exec(ctx, `UPDATE crypto_assets SET certificate_fingerprint=$2 WHERE tenant_id=$1 AND kind='certificate-key'`, tenant, fingerprint); err != nil {
			t.Fatalf("valid observed fingerprint rejected: %v", err)
		}
	}
	count, checksum = checksumQuery(t, ctx, pool, beforeQuery)
	_, validate := splitMigrationsAtVersion(t, 223)
	applyMigrationFiles(t, ctx, pool, []migrationFile{validate})
	constraintValidated(true)
	if gotCount, gotChecksum := checksumQuery(t, ctx, pool, beforeQuery); gotCount != count || gotChecksum != checksum {
		t.Fatalf("0223 changed retained evidence: before %d/%s, after %d/%s", count, checksum, gotCount, gotChecksum)
	}
}
