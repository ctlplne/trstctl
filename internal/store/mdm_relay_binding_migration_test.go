// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0264RetiresOnlyUnboundMDMWork(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 264)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	for _, tenant := range []string{tenantA, tenantB} {
		_, err := pool.Exec(ctx, `INSERT INTO mdm_poll_schedules
			(tenant_id, mdm, base_url, token_ref, interval_seconds, enabled, execution)
			VALUES ($1, 'jamf', 'https://mdm.example.test', 'secret://mdm/jamf', 600, true, 'relay')`, tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct{ key, destination, status string }{
			{"unbound", "mdm.sync", "pending"},
			{"completed", "mdm.sync", "delivered"},
			{"other-job", "cmdb.sync", "pending"},
		} {
			_, err := pool.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status)
				VALUES ($1, $2, '{}', $3, $4)`, tenant, row.destination, row.key, row.status)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	for _, tenant := range []string{tenantA, tenantB} {
		var enabled bool
		var relayID *string
		var lastError string
		if err := pool.QueryRow(ctx, `SELECT enabled, required_agent_id::text, last_error
			FROM mdm_poll_schedules WHERE tenant_id=$1 AND mdm='jamf'`, tenant).Scan(&enabled, &relayID, &lastError); err != nil {
			t.Fatal(err)
		}
		if enabled || relayID != nil || !strings.Contains(lastError, "select one enrolled network relay") {
			t.Fatalf("legacy tenant %s retained unsafe enabled state: enabled=%v relay=%v error=%q", tenant, enabled, relayID, lastError)
		}
		for _, row := range []struct{ key, want string }{
			{"unbound", "failed"}, {"completed", "delivered"}, {"other-job", "pending"},
		} {
			var got string
			if err := pool.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenant, row.key).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != row.want {
				t.Fatalf("tenant %s %s status=%s want=%s", tenant, row.key, got, row.want)
			}
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE mdm_poll_schedules SET enabled=true WHERE tenant_id=$1 AND mdm='jamf'`, tenantA); err == nil {
		t.Fatal("storage accepted an enabled MDM schedule with no exact network relay")
	}
}
