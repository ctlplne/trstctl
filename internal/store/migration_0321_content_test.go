// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 0321 adds the rotation columns to tenant_key_domains. An existing
// domain keeps every value it had and starts with no next generation and no
// rotation; the new checks refuse a rotating row without its next generation
// and a next generation that skips one.
func TestMigration0321KeepsKeyDomainsAndStartsWithNoNextGeneration(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 321)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "32100000-0000-4000-8000-000000000001"
	insert := `INSERT INTO tenant_key_domains
		(tenant_id, domain_id, generation, protection_mode, state, wrapper_kind, wrapper_id,
		 wrapped_domain_kek, operation_id, operation_kind, operation_status, progress_completed,
		 progress_total, legacy_history_exposure, last_transition_event_id, last_transition_type,
		 last_transition_at, last_transition_sequence, created_at, updated_at)
		VALUES ($1, '32100000-0000-4000-8000-0000000000d1', 1, 'tenant_domain', $2, 'local_file',
		 'tenant-wrapper', '\x0102'::bytea, '32100000-0000-4000-8000-0000000000e1', 'migrate',
		 'completed', 13, 13, 'external_archives_possible', 'event-1',
		 'tenant.key_domain.migration_completed', '2026-10-01T00:00:00Z', 7,
		 '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`
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
	if err := withTenant(t, insert, tenant, "partial"); err != nil {
		t.Fatalf("seed pre-0321 key domain: %v", err)
	}
	const stable = `SELECT tenant_id::text, domain_id::text, generation, state, wrapper_kind, wrapper_id,
		encode(wrapped_domain_kek, 'hex'), operation_kind, operation_status, progress_completed,
		progress_total, legacy_history_exposure, last_transition_sequence
		FROM tenant_key_domains ORDER BY tenant_id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0321 changed key-domain content: %d/%s before, %d/%s after",
			beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var invented int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_key_domains
		WHERE next_generation <> 0 OR next_wrapper_kind <> '' OR next_wrapper_id <> ''
		   OR next_wrapped_domain_kek IS NOT NULL OR rotated_at IS NOT NULL`).Scan(&invented); err != nil || invented != 0 {
		t.Fatalf("0321 invented a rotation on an existing domain: count=%d err=%v", invented, err)
	}

	for name, statement := range map[string]string{
		"rotating without a next generation": `UPDATE tenant_key_domains SET state = 'rotating', operation_kind = 'rotate'`,
		"next generation that skips one": `UPDATE tenant_key_domains SET next_generation = 3, next_wrapper_kind = 'local_file',
			next_wrapper_id = 'tenant-wrapper', next_wrapped_domain_kek = '\x03'::bytea, state = 'rotating'`,
		"half a next generation": `UPDATE tenant_key_domains SET next_generation = 2, state = 'rotating'`,
	} {
		if err := withTenant(t, statement); err == nil {
			t.Fatalf("0321 accepted a key domain with %s", name)
		}
	}
	if err := withTenant(t, `UPDATE tenant_key_domains SET next_generation = 2, next_wrapper_kind = 'local_file',
		next_wrapper_id = 'tenant-wrapper', next_wrapped_domain_kek = '\x03'::bytea, state = 'rotating',
		operation_kind = 'rotate', operation_status = 'running'`); err != nil {
		t.Fatalf("0321 refused a well-formed rotation: %v", err)
	}
}
