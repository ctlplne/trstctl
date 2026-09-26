// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0226RetainsUncertainRemoteDeliveries(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 226)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	cases := []struct {
		status            string
		attempts, pending int
	}{
		{"pending", 0, 0}, {"pending", 1, 1}, {"processing", 1, 1},
		{"failed", 1, 1}, {"delivered", 1, 0}, {"delivered", 2, 1},
	}
	for _, tenant := range []string{tenantA, tenantB} {
		for i, tc := range cases {
			if _, err := pool.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,status,attempts)
				VALUES ($1,'lifetime.probe','{}',$2,$3,$4)`, tenant, fmt.Sprint(i), tc.status, tc.attempts); err != nil {
				t.Fatal(err)
			}
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	for _, tenant := range []string{tenantA, tenantB} {
		for i, tc := range cases {
			var status string
			var attempts, pending int
			if err := pool.QueryRow(ctx, `SELECT status, attempts, cardinality(receiver_pending_ids) FROM outbox
				WHERE tenant_id=$1 AND idempotency_key=$2`, tenant, fmt.Sprint(i)).Scan(&status, &attempts, &pending); err != nil {
				t.Fatal(err)
			}
			if status != tc.status || attempts != tc.attempts || pending != tc.pending {
				t.Fatalf("migration changed delivery or lost uncertainty: tenant=%s case=%d status=%s attempts=%d pending=%d", tenant, i, status, attempts, pending)
			}
		}
	}
}
