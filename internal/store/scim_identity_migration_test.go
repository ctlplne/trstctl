// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A failed concurrent unique build leaves an invalid PostgreSQL index. The
// retry must repair it, preserve existing membership evidence, and enforce
// case-insensitive aliases within (but never across) tenants.
func TestSCIMMigrationPreservesMembersAndRecoversInvalidUniqueIndex(t *testing.T) {
	ctx := t.Context()
	prefix, expansion := splitMigrationsAtVersion(t, 220)
	_, indexMigration := splitMigrationsAtVersion(t, 221)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_members
		 (tenant_id,subject,display_name,roles,source,status,created_at,updated_at)
		 SELECT $1, 'member-' || n, 'Existing ' || n, ARRAY['operator'], 'manual',
		 CASE WHEN n%2=0 THEN 'offboarded' ELSE 'active' END,
		 '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z'
		 FROM generate_series(1,100) n`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	stable := `SELECT tenant_id::text,subject,display_name,roles::text,source,status,
	 created_at::text,updated_at::text FROM tenant_members ORDER BY tenant_id,subject`
	beforeCount, beforeHash := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{expansion})
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `UPDATE tenant_members SET scim_identity=
		 '{"user_name":"Alias@example.test","external_id":"member-1","subject_attribute":"externalId"}'::jsonb
		 WHERE tenant_id=$1 AND subject='member-1'`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_members SET scim_identity=
	 '{"user_name":"ALIAS@example.test","external_id":"member-2","subject_attribute":"externalId"}'::jsonb
	 WHERE tenant_id=$1 AND subject='member-2'`, tenantA); err != nil {
		t.Fatal(err)
	}
	var createSQL string
	for _, statement := range splitStatements(indexMigration.body) {
		if strings.HasPrefix(strings.TrimSpace(stripSQLLineComments(statement.sql)), "CREATE UNIQUE INDEX CONCURRENTLY") {
			createSQL = statement.sql
		}
	}
	if createSQL == "" {
		t.Fatal("missing concurrent unique-index build")
	}
	_, err = pool.Exec(ctx, createSQL)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate aliases must fail the initial build: %v", err)
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT indisvalid FROM pg_index
	 WHERE indexrelid='tenant_members_scim_user_name_idx'::regclass`).Scan(&valid); err != nil || valid {
		t.Fatalf("expected a real failed-build invalid index: valid=%t err=%v", valid, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_members SET scim_identity=NULL
	 WHERE tenant_id=$1 AND subject='member-2'`, tenantA); err != nil {
		t.Fatal(err)
	}
	bindings := `SELECT tenant_id::text,subject,scim_identity::text FROM tenant_members
	 WHERE scim_identity IS NOT NULL ORDER BY tenant_id,subject`
	boundCount, boundHash := checksumQuery(t, ctx, pool, bindings)
	applyMigrationFiles(t, ctx, pool, []migrationFile{indexMigration})
	assertIndexReady(t, ctx, pool, "tenant_members_scim_user_name_idx")
	afterCount, afterHash := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 200 || beforeCount != afterCount || beforeHash != afterHash {
		t.Fatalf("SCIM migration changed existing members: before=%d/%s after=%d/%s", beforeCount, beforeHash, afterCount, afterHash)
	}
	if n, hash := checksumQuery(t, ctx, pool, bindings); n != 2 || n != boundCount || hash != boundHash {
		t.Fatal("SCIM index recovery changed tenant-bound aliases")
	}
	_, err = pool.Exec(ctx, `UPDATE tenant_members SET scim_identity='{"user_name":"alias@example.test"}'::jsonb
	 WHERE tenant_id=$1 AND subject='member-2'`, tenantA)
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("recovered index did not reject a case-insensitive same-tenant collision: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint
	 WHERE conrelid='tenant_members'::regclass AND conname='tenant_members_scim_identity_object'`).Scan(&valid); err != nil || !valid {
		t.Fatalf("SCIM object constraint was not validated: valid=%t err=%v", valid, err)
	}
	_, err = pool.Exec(ctx, `UPDATE tenant_members SET scim_identity='[]'::jsonb
	 WHERE tenant_id=$1 AND subject='member-2'`, tenantA)
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("object constraint accepted an array: %v", err)
	}
}
