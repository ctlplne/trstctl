// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBrokerMetadataUpgradePreservesPopulatedTenantRowsAndBuildsOnlineIndex(t *testing.T) {
	ctx := t.Context()
	prefix, column := splitMigrationsAtVersion(t, 200)
	_, index := splitMigrationsAtVersion(t, 201)
	if column.noTx || !index.noTx {
		t.Fatal("column must be transactional; online index must not be")
	}
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	for _, tenantID := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'broker-upgrade')`, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO certificates
			(id, tenant_id, subject, fingerprint, source, issuance_idempotency_key)
			VALUES (gen_random_uuid(), $1, 'preserve this subject', 'same-fingerprint', 'broker:k8s_sat', 'broker-issue:legacy-key')`, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{column, index})
	// PostgreSQL may have completed the concurrent DDL before a process loses
	// its migration receipt. Repeating the no-transaction file must converge.
	applyMigrationFiles(t, ctx, pool, []migrationFile{index})
	for _, tenantID := range []string{tenantA, tenantB} {
		var subject, source, key string
		var unknown bool
		if err := pool.QueryRow(ctx, `SELECT subject, source, issuance_idempotency_key, broker_issuance IS NULL
			FROM certificates WHERE tenant_id = $1 AND fingerprint = 'same-fingerprint'`, tenantID).
			Scan(&subject, &source, &key, &unknown); err != nil {
			t.Fatal(err)
		}
		if subject != "preserve this subject" || source != "broker:k8s_sat" || key != "broker-issue:legacy-key" || !unknown {
			t.Fatal("upgrade changed legacy data or invented broker metadata")
		}
	}
	var valid, ready, constraintValidated bool
	if err := pool.QueryRow(ctx, `SELECT i.indisvalid, i.indisready FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'certificates_broker_history_idx'`).Scan(&valid, &ready); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = 'certificates_broker_issuance_object'`).Scan(&constraintValidated); err != nil {
		t.Fatal(err)
	}
	if !valid || !ready || !constraintValidated {
		t.Fatal("upgrade did not leave a valid/ready index and validated constraint")
	}
	if _, err := pool.Exec(ctx, `UPDATE certificates SET broker_issuance = '[]'::jsonb WHERE tenant_id = $1`, tenantA); err == nil {
		t.Fatal("broker metadata accepted a non-object")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	var neighbors int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id = $1`, tenantB).Scan(&neighbors); err != nil {
		t.Fatal(err)
	}
	if neighbors != 0 {
		t.Fatal("upgraded certificate table leaked neighbor rows under the application role")
	}
}
