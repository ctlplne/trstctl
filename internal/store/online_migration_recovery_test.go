// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/store"
)

// Every fixture uses the exact populated N-1 schema, with honest original
// ledger identities. Only this owned database may be interrupted or malformed.
func prepareHistoricalOnlineUpgrade(t *testing.T, version int) (*store.Store, *pgxpool.Pool, migrationFile, []string) {
	t.Helper()
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, version)
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
	for i, tenant := range []string{tenantA, tenantB} {
		id := fmt.Sprintf("71100000-0000-4000-8000-%012d", i+1)
		var seed string
		if version == 211 {
			seed = `INSERT INTO connector_delivery_receipts
			 (id,tenant_id,destination,connector,target,status,attempts,fingerprint,created_at,updated_at)
			 VALUES ($1,$2,'connector.rollback','nginx','original-target','failed',7,'original-leaf',now(),now())`
		} else {
			seed = `INSERT INTO notification_delivery_receipts
			 (id,tenant_id,destination,notification_key_digest,payload_digest,channel,attempts,delivered_at)
			 VALUES ($1,$2,'notification.send','original-command','original-payload','email',7,now())`
		}
		if _, err := pool.Exec(ctx, seed, id, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var statements []string
	for _, statement := range splitStatements(target.body) {
		if text := strings.TrimSpace(stripSQLLineComments(statement.sql)); text != "" {
			statements = append(statements, text)
		}
	}
	if len(statements) != 2 || !strings.Contains(statements[0], "ADD COLUMN") {
		t.Fatal("historical fixture changed")
	}
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, pool, target, statements
}

func assertHistoricalOnlineLedger(t *testing.T, pool *pgxpool.Pool, target migrationFile) {
	t.Helper()
	var name, digest, plan, executed string
	if err := pool.QueryRow(t.Context(), `SELECT name,checksum,execution_plan,execution_checksum
	 FROM schema_migrations WHERE version=$1`, target.version).Scan(&name, &digest, &plan, &executed); err != nil {
		t.Fatal(err)
	}
	execution, err := store.OnlineMigrationExecutionSQLForTest(target.name, []byte(target.body))
	if err != nil {
		t.Fatal(err)
	}
	if name != target.name || digest != normalizedMigrationDigest([]byte(target.body)) || plan != "historical-online-v1" || executed != normalizedMigrationDigest([]byte(execution)) {
		t.Fatalf("migration identity/provenance mismatch: %q %q %q %q", name, digest, plan, executed)
	}
}

func TestHistoricalOnlineMigrationRecoversInterruptedBuilds(t *testing.T) {
	for _, version := range []int{211, 219} {
		for _, phase := range []string{"unstarted", "expanded", "built", "invalid-index"} {
			t.Run(fmt.Sprintf("%d/%s", version, phase), func(t *testing.T) {
				ctx := t.Context()
				s, pool, target, statements := prepareHistoricalOnlineUpgrade(t, version)
				table, index := "connector_delivery_receipts", "connector_rollback_receipts_unordered"
				if version == 219 {
					table, index = "notification_delivery_receipts", "notification_delivery_receipts_command_idx"
				}
				beforeSQL := "SELECT tenant_id::text,id::text,to_jsonb(o)::text FROM " + table + " o WHERE tenant_id IN ('" + tenantA + "','" + tenantB + "') ORDER BY tenant_id,id"
				beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, beforeSQL)
				if beforeCount != 2 {
					t.Fatal("expected two populated tenant rows")
				}
				if phase != "unstarted" {
					if _, err := pool.Exec(ctx, statements[0]); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "built" {
					if _, err := pool.Exec(ctx, statements[1]); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "invalid-index" {
					writer, err := pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = writer.Rollback(context.Background()) }()
					if _, err := writer.Exec(ctx, "UPDATE "+table+" SET attempts=attempts+1 WHERE tenant_id=$1", tenantB); err != nil {
						t.Fatal(err)
					}
					builder, err := pool.Acquire(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer builder.Release()
					if _, err := builder.Exec(ctx, "SET lock_timeout='100ms'"); err != nil {
						t.Fatal(err)
					}
					_, err = builder.Exec(ctx, strings.Replace(statements[1], "CREATE INDEX", "CREATE INDEX CONCURRENTLY", 1))
					var pgerr *pgconn.PgError
					if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
						t.Fatalf("expected a real interrupted build, got %v", err)
					}
					if err := writer.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
					var valid bool
					if err := pool.QueryRow(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid=$1::regclass`, "public."+index).Scan(&valid); err != nil {
						t.Fatal(err)
					}
					if valid {
						t.Fatal("interrupted build unexpectedly valid")
					}
				}
				if err := s.Migrate(ctx); err != nil {
					t.Fatalf("recover %s: %v", phase, err)
				}
				assertIndexReady(t, ctx, pool, index)
				assertHistoricalOnlineLedger(t, pool, target)
				remove := "-'latest_event_sequence'"
				if version == 219 {
					remove = "-ARRAY['routing_source','routing_policy_id','routing_policy_scope','routing_policy_digest']"
				}
				afterSQL := strings.Replace(beforeSQL, "to_jsonb(o)::text", "(to_jsonb(o)"+remove+")::text", 1)
				afterCount, afterChecksum := checksumQuery(t, ctx, pool, afterSQL)
				if afterCount != beforeCount || afterChecksum != beforeChecksum {
					t.Fatalf("upgrade changed historical row content: %d/%s -> %d/%s", beforeCount, beforeChecksum, afterCount, afterChecksum)
				}
				if err := s.Migrate(ctx); err != nil {
					t.Fatalf("repeat completed migration: %v", err)
				}
				assertHistoricalOnlineLedger(t, pool, target)
			})
		}
	}
}

func TestHistoricalOnlineMigrationRefusesSchemaLookalikes(t *testing.T) {
	for _, tc := range []struct {
		version            int
		name, mutate, want string
	}{
		{211, "wrong-index", `CREATE INDEX connector_rollback_receipts_unordered ON connector_delivery_receipts (id)`, "different definition"},
		{219, "wrong-index", `CREATE INDEX notification_delivery_receipts_command_idx ON notification_delivery_receipts (tenant_id)`, "different definition"},
		{211, "wrong-column", `ALTER TABLE connector_delivery_receipts ALTER COLUMN latest_event_sequence SET DEFAULT 9`, "mismatched column"},
		{219, "partial-columns", `ALTER TABLE notification_delivery_receipts DROP COLUMN routing_source`, "partial column expansion"},
		{211, "weaker-check", `ALTER TABLE connector_delivery_receipts DROP CONSTRAINT connector_delivery_receipts_latest_event_sequence_check;
		 ALTER TABLE connector_delivery_receipts ADD CONSTRAINT connector_delivery_receipts_latest_event_sequence_check CHECK (latest_event_sequence>=-1)`, "mismatched constraint"},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.version, tc.name), func(t *testing.T) {
			s, pool, _, statements := prepareHistoricalOnlineUpgrade(t, tc.version)
			if _, err := pool.Exec(t.Context(), statements[0]); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), tc.mutate); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(t.Context()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("lookalike was not refused: %v", err)
			}
			var recorded bool
			if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, tc.version).Scan(&recorded); err != nil {
				t.Fatal(err)
			}
			if recorded {
				t.Fatal("refused migration was recorded as applied")
			}
		})
	}
}

func TestHistoricalOnlineMigrationExpansionLockFailureIsRetryable(t *testing.T) {
	for _, version := range []int{211, 219} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s, pool, target, _ := prepareHistoricalOnlineUpgrade(t, version)
			table := "connector_delivery_receipts"
			if version == 219 {
				table = "notification_delivery_receipts"
			}
			writer, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(context.Background()) }()
			if _, err := writer.Exec(t.Context(), "UPDATE "+table+" SET attempts=attempts+1 WHERE tenant_id=$1", tenantA); err != nil {
				t.Fatal(err)
			}
			err = s.Migrate(t.Context())
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
				t.Fatalf("blocked expansion did not fail at lock timeout: %v", err)
			}
			var recorded bool
			if err := pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&recorded); err != nil {
				t.Fatal(err)
			}
			if recorded {
				t.Fatal("failed expansion was recorded as applied")
			}
			if err := writer.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatalf("retry after lock release: %v", err)
			}
			assertHistoricalOnlineLedger(t, pool, target)
		})
	}
}

func TestHistoricalOnlineMigrationPreservesAlreadyAppliedProvenance(t *testing.T) {
	for _, version := range []int{211, 219} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s, pool, target, _ := prepareHistoricalOnlineUpgrade(t, version)
			applyMigrationFiles(t, t.Context(), pool, []migrationFile{target})
			if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations (version,name,checksum) VALUES ($1,$2,$3)`, version, target.name, normalizedMigrationDigest([]byte(target.body))); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			table := "connector_delivery_receipts"
			if version == 219 {
				table = "notification_delivery_receipts"
			}
			writer, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(context.Background()) }()
			if _, err := writer.Exec(t.Context(), "UPDATE "+table+" SET attempts=attempts+1 WHERE tenant_id=$1", tenantA); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatalf("already-applied migration was rerun behind active writer: %v", err)
			}
			var unchanged bool
			if err := pool.QueryRow(t.Context(), `SELECT name=$2 AND checksum=$3 AND execution_plan IS NULL AND execution_checksum IS NULL
			 FROM schema_migrations WHERE version=$1`, version, target.name, normalizedMigrationDigest([]byte(target.body))).Scan(&unchanged); err != nil {
				t.Fatal(err)
			}
			if !unchanged {
				t.Fatal("old transactional ledger identity/provenance was rewritten")
			}
		})
	}
}
