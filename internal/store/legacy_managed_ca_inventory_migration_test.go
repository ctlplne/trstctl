// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0244KeepsOlderResponderOnlyReceiptsUnproven(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 244)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	if _, err := pool.Exec(ctx, `INSERT INTO certificate_metadata_receipts
		(tenant_id,event_sequence,event_id,event_digest,issuance_status,issuance_fingerprint,issuance_time)
		VALUES($1,7,'old-v2', $2,'mint','public-fingerprint',now())`, tenantA, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE projection_checkpoint SET applied_seq=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	var projected bool
	if err := pool.QueryRow(ctx, `SELECT legacy_inventory_projected FROM certificate_metadata_receipts
		WHERE tenant_id=$1 AND event_id='old-v2'`, tenantA).Scan(&projected); err != nil || projected {
		t.Fatalf("upgrade invented inventory completion: projected=%t error=%v", projected, err)
	}
	var applied, checked int64
	if err := pool.QueryRow(ctx, `SELECT applied_seq,legacy_managed_ca_inventory_checked_through
		FROM projection_checkpoint WHERE id=1`).Scan(&applied, &checked); err != nil || applied != 7 || checked != 0 {
		t.Fatalf("upgrade skipped old projected history: applied=%d checked=%d error=%v", applied, checked, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO certificate_metadata_receipts
		(tenant_id,event_sequence,event_id,event_digest) VALUES($1,8,'rollback-writer',$2)`,
		tenantA, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT legacy_inventory_projected FROM certificate_metadata_receipts
		WHERE tenant_id=$1 AND event_id='rollback-writer'`, tenantA).Scan(&projected); err != nil || projected {
		t.Fatalf("older binary manufactured inventory proof: projected=%t error=%v", projected, err)
	}
}
