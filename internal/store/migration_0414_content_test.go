// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
)

func TestMigration0414KeepsLegacyRotationsWithoutInventingPreparation(t *testing.T) {
	const stable = `SELECT (to_jsonb(c)-'provider_binding'-'sealed_preparation')::text
 FROM secret_static_rotation_commands c ORDER BY tenant_id,id`
	runPopulatedDefaultMigrationHarness(t, 414, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenant := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `INSERT INTO secret_static_rotation_commands
   (tenant_id,id,tenant_epoch,provider,secret_key,old_ref,phase,expected_version,result_version,
   sealed_old,sealed_new,idempotency_key_digest,request_binding,created_at,updated_at)
   VALUES ($1,$2,'owned-epoch','directory','service','owned-account',$3,7,8,
   '\x010203'::bytea,'\x040506'::bytea,$4,$4,'2026-11-01T00:00:00Z','2026-11-01T00:01:00Z')`,
					tenant, fmt.Sprintf("41400000-0000-4000-8000-%012d", index+1), []string{"staged", "rolled_back"}[index], strings.Repeat("a", 64)); err != nil {
					t.Fatal(err)
				}
			}
		}, func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows, unprepared int
			if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE provider_binding='' AND sealed_preparation IS NULL)
  FROM secret_static_rotation_commands`).Scan(&rows, &unprepared); err != nil || rows != want || unprepared != want {
				t.Fatalf("legacy preparation rows=%d unprepared=%d want=%d err=%v", rows, unprepared, want, err)
			}
			if _, err := pool.Exec(ctx, `UPDATE secret_static_rotation_commands SET provider_binding='wrong'
  WHERE tenant_id=$1`, tenantA); err == nil {
				t.Fatal("invalid native configuration binding accepted")
			}
			if _, err := pool.Exec(ctx, `UPDATE secret_static_rotation_commands SET provider_binding=$2,sealed_preparation='\x070809'::bytea
  WHERE tenant_id=$1`, tenantA, strings.Repeat("b", 64)); err != nil {
				t.Fatal(err)
			}
			var foreignUnprepared bool
			if err := pool.QueryRow(ctx, `SELECT provider_binding='' AND sealed_preparation IS NULL
  FROM secret_static_rotation_commands WHERE tenant_id=$1`, tenantB).Scan(&foreignUnprepared); err != nil || !foreignUnprepared {
				t.Fatalf("foreign legacy row changed: %v", err)
			}
		})
}
