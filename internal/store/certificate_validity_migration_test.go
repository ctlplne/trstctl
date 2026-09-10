// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0209PreservesUnknownValidityAndOrdersAnchorWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	prefix, target := splitMigrationsAtVersion(t, 209)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Historical SQL fixtures only. Seed before the metadata-order triggers,
	// then run the actual populated 0208 -> 0209 upgrade.
	applyMigrationFiles(t, ctx, pool, prefix[:len(prefix)-2])
	seedFirstLeafMigrationContent(t, ctx, pool)
	applyMigrationFiles(t, ctx, pool, prefix[len(prefix)-2:])
	content := func() string {
		t.Helper()
		var raw string
		if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(c)-'validity_anchor' ORDER BY tenant_id,id)::text FROM certificates c`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := content()
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if content() != before {
		t.Fatal("0209 changed historical certificate content")
	}
	var unknown int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE validity_anchor IS NULL`).Scan(&unknown); err != nil || unknown != 2 {
		t.Fatalf("0209 invented issuance timestamps: unknown=%d error=%v", unknown, err)
	}
	for _, foreign := range []bool{false, true} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
			t.Fatal(err)
		}
		targetTenant, wantRows := tenantA, int64(1)
		if foreign {
			targetTenant, wantRows = tenantB, 0
		}
		// NULL -> NULL still names the new column: both the row trigger and
		// the zero-row statement trigger must observe it under the tenant fence.
		tag, err := tx.Exec(ctx, `UPDATE certificates SET validity_anchor=NULL WHERE tenant_id=$1`, targetTenant)
		if err != nil || tag.RowsAffected() != wantRows {
			t.Fatalf("anchor write RLS: rows=%d want=%d error=%v", tag.RowsAffected(), wantRows, err)
		}
		var marked bool
		if err := tx.QueryRow(ctx, `SELECT unknown_write FROM certificate_metadata_watermarks WHERE tenant_id=$1`, tenantA).Scan(&marked); err != nil || !marked {
			t.Fatalf("anchor write escaped metadata ordering: %t %v", marked, err)
		}
		var neighbors int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id=$1`, tenantB).Scan(&neighbors); err != nil || neighbors != 0 {
			t.Fatalf("neighbor certificate visible: %d %v", neighbors, err)
		}
		if !foreign {
			_, err = tx.Exec(ctx, `UPDATE certificates SET validity_anchor='2026-09-10T00:00:00Z' WHERE tenant_id=$1`, tenantA)
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "certificate_validity_anchor_bounds" {
				t.Fatalf("anchor without signed bounds accepted: %v", err)
			}
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
