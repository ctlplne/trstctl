// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testMigration0518ExternalObserverConfigurerStartsUnknown(t *testing.T) {
	const stable = `SELECT tenant_id::text, id::text, name, events_url,
		credential_ref, enabled::text, created_at::text, updated_at::text,
		event_sequence::text FROM external_observers ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 518, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for i, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `INSERT INTO external_observers
					(tenant_id, id, name, events_url, credential_ref,
					 enabled, created_at, updated_at, event_sequence)
					VALUES ($1,$2,$3,'https://observer.example.test/events',
					 'secret://observers/legacy',true,now(),now(),$4)`,
					tenantID, fmt.Sprintf("18000000-0000-4000-8000-%012d", i+1),
					fmt.Sprintf("legacy-observer-%d", i), i+1); err != nil {
					t.Fatalf("seed pre-0518 observer for %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var unknown bool
			if err := pool.QueryRow(ctx, `SELECT count(*),
				bool_and(configured_by = '' AND configured_by_ref = '')
				FROM external_observers WHERE tenant_id IN ($1,$2)`, tenantA, tenantB).
				Scan(&rows, &unknown); err != nil {
				t.Fatal(err)
			}
			if rows != want || !unknown {
				t.Fatalf("0518 fabricated legacy observer authority: rows=%d want=%d unknown=%t", rows, want, unknown)
			}
		})
}
