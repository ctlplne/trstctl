// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Upgrading a populated control plane must preserve the original command and
// receipt evidence. New columns must not invent execution or routing authority.
func TestRecentLifecycleMigrationsPreserveTenantEvidence(t *testing.T) {
	for _, tc := range []struct {
		name            string
		version         int
		seed            string
		before          string
		after           string
		unsafeDefault   string
		invalidWrite    string
		invalidSQLState string
		index           string
	}{
		{
			name: "0210_host_rotation_receipt_lookup", version: 210, invalidSQLState: "23514",
			seed: `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,status,attempts)
			 VALUES ($1,'endpoint.renew',$2,'retained-command','failed',7)`,
			before: `SELECT tenant_id::text,id::text,to_jsonb(o)::text FROM outbox o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			after: `SELECT tenant_id::text,id::text,(to_jsonb(o)-ARRAY['host_rotation_scan_generation','host_rotation_scan_through','host_rotation_scan_next','host_rotation_delivery_sequence','host_rotation_custody_sequence','host_rotation_result_sequence'])::text FROM outbox o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			unsafeDefault: `SELECT count(*) FROM outbox WHERE tenant_id=ANY($1::uuid[]) AND
			 (host_rotation_scan_generation<>'' OR host_rotation_scan_through<>0 OR host_rotation_scan_next<>0
			 OR host_rotation_delivery_sequence<>0 OR host_rotation_custody_sequence<>0 OR host_rotation_result_sequence<>0)`,
			invalidWrite: `UPDATE outbox SET host_rotation_delivery_sequence=-1 WHERE tenant_id=$1 AND idempotency_key='retained-command'`,
		},
		{
			name: "0211_connector_rollback_projection_order", version: 211, invalidSQLState: "23514",
			seed: `INSERT INTO connector_delivery_receipts
			 (id,tenant_id,destination,connector,target,status,attempts,fingerprint,created_at,updated_at)
			 VALUES ($1::uuid,$1,'connector.rollback','nginx','original-target','failed',7,convert_from($2,'UTF8'),'2026-09-01T01:00:00Z','2026-09-01T01:01:00Z')`,
			before: `SELECT tenant_id::text,id::text,to_jsonb(o)::text FROM connector_delivery_receipts o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			after: `SELECT tenant_id::text,id::text,(to_jsonb(o)-'latest_event_sequence')::text FROM connector_delivery_receipts o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			unsafeDefault: `SELECT count(*) FROM connector_delivery_receipts WHERE tenant_id=ANY($1::uuid[]) AND latest_event_sequence IS DISTINCT FROM 0`,
			invalidWrite:  `UPDATE connector_delivery_receipts SET latest_event_sequence=-1 WHERE tenant_id=$1`,
			index:         "connector_rollback_receipts_unordered",
		},
		{
			name: "0218_agent_job_retry_deadline", version: 218, invalidSQLState: "23502",
			seed: `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,status,attempts,next_attempt_at)
			 VALUES ($1,'endpoint.renew',$2,'retained-command','failed',7,'2027-01-01T00:00:00Z')`,
			before: `SELECT tenant_id::text,id::text,to_jsonb(o)::text FROM outbox o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			after: `SELECT tenant_id::text,id::text,(to_jsonb(o)-'agent_next_attempt_at')::text FROM outbox o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			unsafeDefault: `SELECT count(*) FROM outbox WHERE tenant_id=ANY($1::uuid[]) AND agent_next_attempt_at IS DISTINCT FROM '1970-01-01T00:00:00Z'::timestamptz`,
			invalidWrite:  `UPDATE outbox SET agent_next_attempt_at=NULL WHERE tenant_id=$1 AND idempotency_key='retained-command'`,
		},
		{
			name: "0219_notification_delivery_routing", version: 219, invalidSQLState: "23502",
			seed: `INSERT INTO notification_delivery_receipts
			 (tenant_id,id,destination,notification_key_digest,payload_digest,channel,attempts,delivered_at)
			 VALUES ($1,'same-receipt','notification.send','original-command',convert_from($2,'UTF8'),'email',7,'2026-09-01T01:00:00Z')`,
			before: `SELECT tenant_id::text,id,to_jsonb(o)::text FROM notification_delivery_receipts o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			after: `SELECT tenant_id::text,id,(to_jsonb(o)-ARRAY['routing_source','routing_policy_id','routing_policy_scope','routing_policy_digest'])::text FROM notification_delivery_receipts o
			 WHERE tenant_id IN ('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222') ORDER BY tenant_id,id`,
			unsafeDefault: `SELECT count(*) FROM notification_delivery_receipts WHERE tenant_id=ANY($1::uuid[]) AND
			 (routing_source<>'' OR routing_policy_id<>'' OR routing_policy_scope<>'' OR routing_policy_digest<>'')`,
			invalidWrite: `UPDATE notification_delivery_receipts SET routing_source=NULL WHERE tenant_id=$1 AND id='same-receipt'`,
			index:        "notification_delivery_receipts_command_idx",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			prefix, target := splitMigrationsAtVersion(t, tc.version)
			pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			applyMigrationFiles(t, ctx, pool, prefix)
			for _, tenant := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, tc.seed, tenant, []byte("retained-"+tenant)); err != nil {
					t.Fatalf("seed retained evidence: %v", err)
				}
			}
			beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, tc.before)
			if beforeCount != 2 {
				t.Fatalf("expected two populated tenants, got %d rows", beforeCount)
			}
			applyMigrationFiles(t, ctx, pool, []migrationFile{target})
			afterCount, afterChecksum := checksumQuery(t, ctx, pool, tc.after)
			if beforeCount != afterCount || beforeChecksum != afterChecksum {
				t.Fatalf("existing tenant evidence changed: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
			}
			var unsafe int
			if err := pool.QueryRow(ctx, tc.unsafeDefault, []string{tenantA, tenantB}).Scan(&unsafe); err != nil || unsafe != 0 {
				t.Fatalf("migration invented execution, delay or routing evidence: rows=%d error=%v", unsafe, err)
			}
			_, err = pool.Exec(ctx, tc.invalidWrite, tenantA)
			var constraintError *pgconn.PgError
			if !errors.As(err, &constraintError) || constraintError.Code != tc.invalidSQLState {
				t.Fatalf("invalid new metadata must fail its constraint: want SQLSTATE %s, got %v", tc.invalidSQLState, err)
			}
			if tc.index != "" {
				assertIndexReady(t, ctx, pool, tc.index)
			}
		})
	}
}
