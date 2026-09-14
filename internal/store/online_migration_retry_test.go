// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/store"
)

// A retry after committed column expansion must finish its index online. A
// held writer makes the index wait deterministically; another application
// writer must still proceed, and the ledger must retain the shipped SQL digest.
func TestHistoricalIndexMigrationRetryKeepsApplicationWritesAvailable(t *testing.T) {
	for _, tc := range []struct {
		version int
		index   string
		seed    string
		write   string
	}{
		{
			version: 211, index: "connector_rollback_receipts_unordered",
			seed: `INSERT INTO connector_delivery_receipts
			 (id,tenant_id,destination,connector,target,status,attempts,fingerprint,created_at,updated_at)
			 VALUES ($1,$2,'connector.rollback','nginx','original-target','failed',7,'original-leaf',now(),now())`,
			write: `UPDATE connector_delivery_receipts SET attempts=attempts+1 WHERE tenant_id=$1 AND id=$2`,
		},
		{
			version: 219, index: "notification_delivery_receipts_command_idx",
			seed: `INSERT INTO notification_delivery_receipts
			 (id,tenant_id,destination,notification_key_digest,payload_digest,channel,attempts,delivered_at)
			 VALUES ($1,$2,'notification.send','original-command','original-payload','email',7,now())`,
			write: `UPDATE notification_delivery_receipts SET attempts=attempts+1 WHERE tenant_id=$1 AND id=$2`,
		},
	} {
		t.Run(fmt.Sprint(tc.version), func(t *testing.T) {
			ctx := t.Context()
			prefix, target := splitMigrationsAtVersion(t, tc.version)
			dsn := createFreshMigrationDatabase(t)
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			applyMigrationFiles(t, ctx, pool, prefix)
			if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
			 version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(), name text, checksum text)`); err != nil {
				t.Fatal(err)
			}
			for _, m := range prefix {
				if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version,name,checksum) VALUES ($1,$2,$3)`,
					m.version, m.name, normalizedMigrationDigest([]byte(m.body))); err != nil {
					t.Fatal(err)
				}
			}
			const firstID = "71100000-0000-4000-8000-000000000001"
			const secondID = "71100000-0000-4000-8000-000000000002"
			for _, tenant := range []string{tenantA, tenantB} {
				id := firstID
				if tenant == tenantB {
					id = secondID
				}
				if _, err := pool.Exec(ctx, tc.seed, id, tenant); err != nil {
					t.Fatal(err)
				}
			}
			// Only the column expansion is committed. The index and final ledger
			// entry are absent: this is the interruption boundary being recovered.
			var statements []sqlStatement
			for _, statement := range splitStatements(target.body) {
				if strings.TrimSpace(stripSQLLineComments(statement.sql)) != "" {
					statements = append(statements, statement)
				}
			}
			if len(statements) != 2 || !strings.Contains(statements[0].sql, "ADD COLUMN") {
				t.Fatal("historical migration fixture changed")
			}
			if _, err := pool.Exec(ctx, statements[0].sql); err != nil {
				t.Fatal(err)
			}
			migrator, err := store.Open(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(migrator.Close)
			writer, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(context.Background()) }()
			if _, err := writer.Exec(ctx, tc.write, tenantA, firstID); err != nil {
				t.Fatal(err)
			}
			migrationCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- migrator.Migrate(migrationCtx) }()
			// Cleanup joins the owned migration worker before closing its pool.
			joined := false
			defer func() {
				cancel()
				_ = writer.Rollback(context.Background())
				if !joined {
					<-done
				}
			}()
			deadline := time.Now().Add(7 * time.Second)
			indexWaiting := false
			for time.Now().Before(deadline) {
				select {
				case err := <-done:
					joined = true
					t.Fatalf("migration stopped before reaching online index construction: %v", err)
				default:
				}
				if err := pool.QueryRow(ctx, `SELECT EXISTS (
				 SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
				 AND state='active' AND query ILIKE $1)`, "%CREATE%INDEX%CONCURRENTLY%"+tc.index+"%").Scan(&indexWaiting); err != nil {
					t.Fatal(err)
				}
				if indexWaiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !indexWaiting {
				t.Fatal("migration did not reach its concurrent index phase within seven seconds")
			}
			applicationCtx, release := context.WithTimeout(ctx, time.Second)
			defer release()
			application, err := pool.Begin(applicationCtx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = application.Rollback(context.Background()) }()
			if _, err := application.Exec(applicationCtx, "SET LOCAL ROLE trstctl_app"); err != nil {
				t.Fatal(err)
			}
			if _, err := application.Exec(applicationCtx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantB); err != nil {
				t.Fatal(err)
			}
			tag, err := application.Exec(applicationCtx, tc.write, tenantB, secondID)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatalf("application write blocked or lost during index construction: rows=%d error=%v", tag.RowsAffected(), err)
			}
			if err := application.Commit(applicationCtx); err != nil {
				t.Fatal(err)
			}
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = <-done
			joined = true
			if err != nil {
				t.Fatalf("finish online migration: %v", err)
			}
			assertIndexReady(t, ctx, pool, tc.index)
			var name, checksum string
			if err := pool.QueryRow(ctx, `SELECT name,checksum FROM schema_migrations WHERE version=$1`, tc.version).Scan(&name, &checksum); err != nil {
				t.Fatal(err)
			}
			if name != target.name || checksum != normalizedMigrationDigest([]byte(target.body)) {
				t.Fatalf("online repair rewrote historical migration identity: %s %s", name, checksum)
			}
			if err := migrator.Migrate(ctx); err != nil {
				t.Fatalf("repeat completed migration: %v", err)
			}
		})
	}
}
