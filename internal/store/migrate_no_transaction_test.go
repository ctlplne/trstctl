package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/store"
)

var createIndexConcurrentlyRe = regexp.MustCompile(`(?i)\bcreate\s+(?:unique\s+)?index\s+concurrently\s+(?:if\s+not\s+exists\s+)?"?([a-z0-9_]+)"?`)

// TestNoTransactionMigration is the SCHEMA-003 acceptance guard: the real
// migration runner must execute embedded no-transaction migrations from a fresh
// database, record their ledger rows only after success, and leave every shipped
// CONCURRENTLY-built index valid. If Migrate regresses to wrapping all migration
// SQL in one transaction, PostgreSQL rejects CREATE INDEX CONCURRENTLY and this
// test fails before the ledger can claim success.
func TestNoTransactionMigration(t *testing.T) {
	ctx := context.Background()
	noTx, createdIndexes := noTransactionConcurrentIndexMigrations(t)
	if len(noTx) == 0 {
		t.Fatal("expected at least one embedded no-transaction concurrent-index migration")
	}
	if len(createdIndexes) == 0 {
		t.Fatal("expected no-transaction migrations to create at least one concurrent index")
	}

	dsn := createFreshMigrationDatabase(t)
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open fresh migration database: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate on fresh database with no-transaction migrations: %v", err)
	}
	for _, name := range noTx {
		version := migrationNumber(name)
		var applied bool
		if err := s.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			t.Fatalf("query migration ledger for %s: %v", name, err)
		}
		if !applied {
			t.Fatalf("no-transaction migration %s ran but was not recorded in schema_migrations", name)
		}
	}
	for _, indexName := range createdIndexes {
		var ready bool
		err := s.Pool().QueryRow(ctx, `
			SELECT i.indisready AND i.indisvalid
			  FROM pg_class c
			  JOIN pg_index i ON i.indexrelid = c.oid
			 WHERE c.relname = $1`, indexName).Scan(&ready)
		if err != nil {
			t.Fatalf("concurrent index %s was not created by no-transaction migration: %v", indexName, err)
		}
		if !ready {
			t.Fatalf("concurrent index %s exists but is not ready and valid", indexName)
		}
	}

	// Re-running Migrate is the retry/idempotency half of the contract: after the
	// ledger rows exist, a second runner must observe them and do no destructive work.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate after no-transaction ledger rows: %v", err)
	}
}

func noTransactionConcurrentIndexMigrations(t *testing.T) ([]string, []string) {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var noTx []string
	var indexes []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("migrations", entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		body := string(raw)
		if !strings.Contains(strings.ToLower(body), "concurrently") {
			continue
		}
		if !strings.Contains(strings.ToLower(body), "-- migrate: no-transaction") &&
			!strings.Contains(strings.ToLower(body), "-- migrate: no-tx") {
			t.Fatalf("%s uses CONCURRENTLY but lacks -- migrate: no-transaction metadata", entry.Name())
		}
		if strings.Contains(strings.ToLower(stripSQLLineComments(body)), "begin;") ||
			strings.Contains(strings.ToLower(stripSQLLineComments(body)), "commit;") {
			t.Fatalf("%s is marked no-transaction but contains explicit BEGIN/COMMIT", entry.Name())
		}
		noTx = append(noTx, entry.Name())
		for _, stmt := range splitStatements(body) {
			sql := stripSQLLineComments(stmt.sql)
			m := createIndexConcurrentlyRe.FindStringSubmatch(sql)
			if m == nil {
				continue
			}
			indexName := strings.ToLower(m[1])
			lower := strings.ToLower(sql)
			if !strings.Contains(lower, "if not exists") &&
				!strings.Contains(strings.ToLower(body), "drop index concurrently if exists "+indexName) {
				t.Fatalf("%s creates %s concurrently without IF NOT EXISTS or a retry-safe DROP INDEX CONCURRENTLY IF EXISTS prelude", entry.Name(), indexName)
			}
			indexes = append(indexes, indexName)
		}
	}
	return noTx, indexes
}

func createFreshMigrationDatabase(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dbName := fmt.Sprintf("trstctl_migration_notx_%d", time.Now().UnixNano())
	admin, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	t.Cleanup(func() { admin.Close() })
	ident := pgx.Identifier{dbName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	})
	return strings.TrimSuffix(testDSN, "/postgres") + "/" + dbName
}
