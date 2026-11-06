// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestMigration0416KeepsCompletedDiscoveryAndAdmitsQueuedIntent(t *testing.T) {
	const stable = `SELECT (to_jsonb(r)-'scan_intent'-'outbox_id')::text FROM pam_discovery_runs r ORDER BY tenant_id,id`
	runPopulatedDefaultMigrationHarness(t, 416, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO pam_discovery_runs(tenant_id,id,provider_id,status,started_at,finished_at,requested_by,accounts)
 VALUES($1,'41600000-0000-4000-8000-000000000001','owned-ad','completed','2026-11-06T00:00:00Z','2026-11-06T00:00:01Z','operator',3)`, tenant); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, want int) {
		var legacy int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_discovery_runs WHERE scan_intent IS NULL AND outbox_id IS NULL AND status='completed'`).Scan(&legacy); err != nil || legacy != want {
			t.Fatal("upgrade invented a provider-read intent", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO pam_discovery_runs(tenant_id,id,provider_id,status,started_at,finished_at,requested_by,scan_intent)
 VALUES($1,'41600000-0000-4000-8000-000000000002','owned-ad','queued',now(),NULL,'operator','{"intent":"owned"}')`, tenantA); err != nil {
			t.Fatal("queued intent rejected", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO pam_discovery_runs(tenant_id,id,provider_id,status,started_at,finished_at,requested_by)
 VALUES($1,'41600000-0000-4000-8000-000000000003','owned-ad','queued',now(),NULL,'operator')`, tenantA); err == nil {
			t.Fatal("same source admitted concurrent queued reads")
		}
		var foreign int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_discovery_runs WHERE tenant_id=$1 AND status='queued'`, tenantB).Scan(&foreign); err != nil || foreign != 0 {
			t.Fatal("upgrade/queue affected foreign source", err)
		}
	})
}
