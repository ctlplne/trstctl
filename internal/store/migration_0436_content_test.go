// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A266: 0436 adds the certificate recording recovery state to the existing
// watermark rows at zero, so the next recording verifies the history from the
// registration once, without changing a watermark or a receipt. Its trigger
// marks a receipt whose sequence, identity or digest changes, or that is
// deleted, for recheck at the lowest such sequence of that tenant only; an
// issuance-status update leaves the mark alone.
func TestMigration0436StartsRecoveryAtZeroAndMarksChangedReceipts(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 436)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant, other = "43600000-0000-4000-8000-000000000001", "43600000-0000-4000-8000-000000000002"
	exec := func(scope, sql string, args ...any) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, scope); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []string{tenant, other} {
		exec(scope, `INSERT INTO certificate_metadata_watermarks(tenant_id,latest_sequence,unknown_write) VALUES($1,9,false)`, scope)
		exec(scope, `INSERT INTO certificate_metadata_receipts(tenant_id,event_sequence,event_id,event_digest)
			VALUES($1::uuid,4,$1::text||'-evt-4',repeat('a',64)),($1::uuid,9,$1::text||'-evt-9',repeat('b',64))`, scope)
	}
	const watermarks = `SELECT tenant_id::text,latest_sequence,unknown_write FROM certificate_metadata_watermarks ORDER BY tenant_id`
	const receipts = `SELECT tenant_id::text,event_sequence,event_id,event_digest,issuance_status,legacy_inventory_projected
		FROM certificate_metadata_receipts ORDER BY tenant_id,event_sequence`
	wCount, wSum := checksumQuery(t, ctx, pool, watermarks)
	rCount, rSum := checksumQuery(t, ctx, pool, receipts)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, sum := checksumQuery(t, ctx, pool, watermarks); wCount != 2 || n != wCount || sum != wSum {
		t.Fatalf("0436 changed watermarks: %d/%s before, %d/%s after", wCount, wSum, n, sum)
	}
	if n, sum := checksumQuery(t, ctx, pool, receipts); rCount != 4 || n != rCount || sum != rSum {
		t.Fatalf("0436 changed receipts: %d/%s before, %d/%s after", rCount, rSum, n, sum)
	}

	state := func(scope string) (through, cursor int64, recheck *int64) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT recovered_through,reverify_cursor,recheck_from FROM certificate_metadata_watermarks
			WHERE tenant_id=$1`, scope).Scan(&through, &cursor, &recheck); err != nil {
			t.Fatal(err)
		}
		return through, cursor, recheck
	}
	expectRecheck := func(when string, want int64) {
		t.Helper()
		_, _, recheck := state(tenant)
		if (want == 0) != (recheck == nil) || (recheck != nil && *recheck != want) {
			t.Fatalf("%s: recheck_from = %v, want %d (0 = none)", when, recheck, want)
		}
		if _, _, untouched := state(other); untouched != nil {
			t.Fatalf("%s marked another tenant's history: %d", when, *untouched)
		}
	}
	if through, cursor, recheck := state(tenant); through != 0 || cursor != 0 || recheck != nil {
		t.Fatalf("an existing watermark starts at %d/%d/%v, want 0/0/none", through, cursor, recheck)
	}
	exec(tenant, `UPDATE certificate_metadata_receipts SET issuance_status='not_mint' WHERE tenant_id=$1 AND event_sequence=9`, tenant)
	expectRecheck("an issuance-status update", 0)
	exec(tenant, `UPDATE certificate_metadata_receipts SET event_digest=repeat('c',64) WHERE tenant_id=$1 AND event_sequence=9`, tenant)
	expectRecheck("a changed digest", 9)
	exec(tenant, `UPDATE certificate_metadata_receipts SET event_id=event_id||'-x' WHERE tenant_id=$1 AND event_sequence=4`, tenant)
	expectRecheck("a changed identity below it", 4)
	exec(tenant, `UPDATE certificate_metadata_watermarks SET recheck_from=NULL WHERE tenant_id=$1`, tenant)
	exec(tenant, `DELETE FROM certificate_metadata_receipts WHERE tenant_id=$1 AND event_sequence=9`, tenant)
	expectRecheck("a deleted receipt", 9)
}
