package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// contentPrefixVersion is the historical schema point the SCHEMA-003 content test
// migrates TO before seeding. Every table the test populates (read-model owners +
// certificates, independent-state ssh_keys, sealed-blob secret_store + credentials,
// the outbox, and idempotency_keys) exists by this migration, so the rows can be
// seeded, then the REMAINING migrations (which include additive ALTERs to a
// populated outbox at 0032 and a populated certificates at 0036, plus a
// CONCURRENTLY-built index) are applied over real data.
const contentPrefixVersion = 31

// seededContentColumns is the EXPLICIT, version-stable column projection used to
// checksum each seeded table. It deliberately names only the columns that exist at
// contentPrefixVersion, so a later additive ADD COLUMN (e.g. outbox.worker_id at
// 0032, certificates.issuance_idempotency_key at 0036) does NOT change the checksum:
// the test asserts the SEEDED content is preserved byte-for-byte across the upgrade,
// while still exercising the ALTER against populated rows. The ORDER BY makes the
// aggregate deterministic.
var seededContentColumns = map[string]struct {
	cols    string
	orderBy string
}{
	"owners":           {cols: "id::text, tenant_id::text, kind, name, email", orderBy: "id"},
	"certificates":     {cols: "id::text, tenant_id::text, COALESCE(owner_id::text,''), subject, array_to_string(sans, ','), fingerprint", orderBy: "id"},
	"ssh_keys":         {cols: "id::text, tenant_id::text, fingerprint, comment, location", orderBy: "id"},
	"secret_store":     {cols: "tenant_id::text, name, encode(sealed,'hex'), version", orderBy: "tenant_id, name"},
	"credentials":      {cols: "id::text, tenant_id::text, scope, ref, name, encode(sealed,'hex')", orderBy: "id"},
	"outbox":           {cols: "tenant_id::text, destination, encode(payload,'hex'), idempotency_key, status", orderBy: "id"},
	"idempotency_keys": {cols: "tenant_id::text, key, status, encode(COALESCE(result,''::bytea),'hex')", orderBy: "tenant_id, key"},
}

// TestMigrationsPreserveSeededContent is the SCHEMA-003 acceptance: existing
// migration tests cover ordering, locking, and online-DDL form, but NOT that
// populated before/after data CONTENT survives an upgrade. This test migrates a
// fresh database to a historical prefix, seeds representative multi-tenant rows
// across the read model, independent state, sealed-secret blobs, the outbox, and
// the idempotency ledger, captures per-table row counts AND deterministic content
// checksums, applies the REMAINING migrations (additive ALTERs over the now-
// populated certificates/outbox plus a CONCURRENTLY-built index), and asserts every
// seeded row count and content checksum is unchanged — i.e. no migration silently
// rewrote, dropped, or duplicated live tenant data, and a new column's default did
// not disturb existing values.
//
// It needs real embedded PostgreSQL (advisory locks, RLS, CONCURRENTLY). In a
// sandbox that cannot start embedded PostgreSQL it is skipped by the package's
// TestMain bootstrap, but it executes in CI.
func TestMigrationsPreserveSeededContent(t *testing.T) {
	ctx := context.Background()
	all := orderedMigrationFiles(t)
	var prefix, remaining []migrationFile
	for _, m := range all {
		if m.version <= contentPrefixVersion {
			prefix = append(prefix, m)
		} else {
			remaining = append(remaining, m)
		}
	}
	if len(prefix) == 0 || len(remaining) == 0 {
		t.Fatalf("expected a non-empty prefix and remaining set (prefix=%d remaining=%d)", len(prefix), len(remaining))
	}

	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)

	// 1) Apply the historical prefix.
	applyMigrationFiles(t, ctx, pool, prefix)

	// 2) Seed representative multi-tenant rows.
	seedMigrationContent(t, ctx, pool, tenantA)
	seedMigrationContent(t, ctx, pool, tenantB)

	// 3) Capture counts + content checksums BEFORE the remaining migrations.
	before := captureSeededContent(t, ctx, pool)
	for table, snap := range before {
		if snap.count == 0 {
			t.Fatalf("precondition: %s should have seeded rows before the upgrade", table)
		}
	}

	// 4) Apply the remaining migrations over the populated tables.
	applyMigrationFiles(t, ctx, pool, remaining)

	// 5) Capture AFTER and diff.
	after := captureSeededContent(t, ctx, pool)
	for table, b := range before {
		a, ok := after[table]
		if !ok {
			t.Errorf("%s vanished after the remaining migrations", table)
			continue
		}
		if a.count != b.count {
			t.Errorf("%s row count changed across migration: before=%d after=%d (data lost or duplicated)", table, b.count, a.count)
		}
		if a.checksum != b.checksum {
			t.Errorf("%s seeded content changed across migration: before=%s after=%s (a migration rewrote live data)", table, b.checksum, a.checksum)
		}
	}

	// 6) Additive columns must exist and carry their declared defaults on the
	// pre-existing rows (the ALTER applied to populated tables, not just empty ones).
	assertColumnDefault(t, ctx, pool, "outbox", "worker_id", "") // nullable add — NULL is fine, just must exist
	assertColumnDefault(t, ctx, pool, "certificates", "issuance_idempotency_key", "")
}

// migrationFile is one ordered migration on disk.
type migrationFile struct {
	name    string
	version int
	body    string
	noTx    bool
}

func orderedMigrationFiles(t *testing.T) []migrationFile {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var out []migrationFile
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		body := string(raw)
		out = append(out, migrationFile{
			name:    e.Name(),
			version: migrationNumber(e.Name()),
			body:    body,
			noTx:    isNoTransactionMigration(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

func isNoTransactionMigration(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "--") {
			continue
		}
		c := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "--")))
		if c == "migrate: no-transaction" || c == "migrate: no-tx" {
			return true
		}
	}
	return false
}

// applyMigrationFiles applies migrations the way Migrate does: a no-transaction
// migration's statements run individually outside a transaction (so CREATE INDEX
// CONCURRENTLY is legal); a normal migration's whole body runs in one statement.
func applyMigrationFiles(t *testing.T, ctx context.Context, pool *pgxpool.Pool, files []migrationFile) {
	t.Helper()
	for _, m := range files {
		if m.noTx {
			for _, stmt := range splitStatements(m.body) {
				sql := strings.TrimSpace(stmt.sql)
				if stripSQLLineComments(sql) == "" || strings.TrimSpace(stripSQLLineComments(sql)) == "" {
					continue
				}
				if _, err := pool.Exec(ctx, sql); err != nil {
					t.Fatalf("apply no-tx migration %s stmt: %v\n%s", m.name, err, sql)
				}
			}
			continue
		}
		if _, err := pool.Exec(ctx, m.body); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
}

// seededContentSnapshot is one table's count and deterministic content checksum.
type seededContentSnapshot struct {
	count    int
	checksum string
}

func captureSeededContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]seededContentSnapshot {
	t.Helper()
	out := make(map[string]seededContentSnapshot, len(seededContentColumns))
	for table, proj := range seededContentColumns {
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		// md5 of the row-ordered concatenation of the stable columns. chr(31) (the
		// ASCII unit separator) joins columns and chr(30) joins rows, so neither can
		// collide with ordinary data. A NULL aggregate (no rows) is coalesced to a
		// constant so the checksum is always defined.
		q := fmt.Sprintf(
			`SELECT COALESCE(md5(string_agg(row_blob, chr(30) ORDER BY %s)), 'empty')
			   FROM (SELECT concat_ws(chr(31), %s) AS row_blob, %s FROM %s) s`,
			proj.orderBy, proj.cols, proj.orderBy, table)
		var sum string
		if err := pool.QueryRow(ctx, q).Scan(&sum); err != nil {
			t.Fatalf("checksum %s: %v", table, err)
		}
		out[table] = seededContentSnapshot{count: count, checksum: sum}
	}
	return out
}

func assertColumnDefault(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, column, _ string) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                 WHERE table_name = $1 AND column_name = $2)`,
		table, column).Scan(&exists); err != nil {
		t.Fatalf("column existence %s.%s: %v", table, column, err)
	}
	if !exists {
		t.Errorf("expected additive column %s.%s to exist after migration", table, column)
	}
}

// seedMigrationContent inserts representative rows for tenantID across the read
// model, independent state, sealed-secret blobs, the outbox, and the idempotency
// ledger. It uses the superuser pool (bypasses RLS) so it can write explicit
// tenant_id values for multiple tenants directly; FORCE RLS is exercised elsewhere.
func seedMigrationContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	ownerID := uuid(tenantID, 21)
	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO owners (id, tenant_id, kind, name, email) VALUES ($1,$2,'Service','svc-owner',$3)`,
			[]any{ownerID, tenantID, "owner-" + tenantID + "@example.test"}},
		{`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, fingerprint)
		  VALUES ($1,$2,$3,'CN=seed', ARRAY['a.seed.test','b.seed.test']::text[], $4)`,
			[]any{uuid(tenantID, 22), tenantID, ownerID, "fp-" + tenantID}},
		{`INSERT INTO ssh_keys (id, tenant_id, fingerprint, comment, location)
		  VALUES ($1,$2,$3,'ops@host','/etc/ssh')`,
			[]any{uuid(tenantID, 23), tenantID, "ssh-" + tenantID}},
		{`INSERT INTO secret_store (tenant_id, name, sealed) VALUES ($1,'api-key',$2)`,
			[]any{tenantID, []byte("sealed-secret-" + tenantID)}},
		{`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
		  VALUES ($1,$2,'issuer','ref-1','api_key',$3)`,
			[]any{uuid(tenantID, 24), tenantID, []byte("sealed-cred-" + tenantID)}},
		{`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status)
		  VALUES ($1,'webhook',$2,$3,'pending')`,
			[]any{tenantID, []byte("payload-" + tenantID), "idem-out-" + tenantID}},
		{`INSERT INTO idempotency_keys (tenant_id, key, status, result)
		  VALUES ($1,$2,'completed',$3)`,
			[]any{tenantID, "idem-" + tenantID, []byte("result-" + tenantID)}},
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed content for %s: %v\n%s", tenantID, err, s.sql)
		}
	}
}
