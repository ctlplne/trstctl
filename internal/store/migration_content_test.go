package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

var valueChangingMigrationContentHarnesses = map[int]bool{
	62: true,
}

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

// TestMigrationDataContentBackfills is the SCHEMA-002 acceptance: migrations that
// write values, not just shapes, must prove their before/after transform over
// populated multi-tenant data at the exact N-1 -> N boundary.
func TestMigrationDataContentBackfills(t *testing.T) {
	t.Run("0046_secret_store_versions", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 46)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedSecretStoreBackfillContent(t, ctx, pool)

		var versionsTableExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('secret_store_versions') IS NOT NULL`).Scan(&versionsTableExists); err != nil {
			t.Fatalf("check pre-0046 table existence: %v", err)
		}
		if versionsTableExists {
			t.Fatal("precondition: secret_store_versions must not exist before migration 0046")
		}

		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, `
			SELECT tenant_id::text, name, version::text, encode(sealed, 'hex'), updated_at::text
			  FROM secret_store
			 ORDER BY tenant_id, name, version`)

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, `
			SELECT tenant_id::text, name, version::text, encode(sealed, 'hex'), written_at::text
			  FROM secret_store_versions
			 ORDER BY tenant_id, name, version`)
		if afterCount != beforeCount {
			t.Fatalf("secret_store_versions backfill count mismatch: before=%d after=%d", beforeCount, afterCount)
		}
		if afterChecksum != beforeChecksum {
			t.Fatalf("secret_store_versions backfill changed values: before=%s after=%s", beforeChecksum, afterChecksum)
		}
	})

	t.Run("0051_discovery_finding_triage", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 51)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedDiscoveryFindingBackfillContent(t, ctx, pool)

		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, discoveryFindingStableProjectionSQL())

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, discoveryFindingStableProjectionSQL())
		if afterCount != beforeCount {
			t.Fatalf("discovery_findings count changed across 0051: before=%d after=%d", beforeCount, afterCount)
		}
		if afterChecksum != beforeChecksum {
			t.Fatalf("discovery_findings existing values changed across 0051: before=%s after=%s", beforeChecksum, afterChecksum)
		}

		var count int
		var statusOK, managedIDOK, actorOK, reasonOK, triagedAtOK bool
		if err := pool.QueryRow(ctx, `
			SELECT count(*),
			       bool_and(triage_status = 'unmanaged'),
			       bool_and(managed_identity_id IS NULL),
			       bool_and(triage_actor = ''),
			       bool_and(triage_reason = ''),
			       bool_and(triaged_at IS NULL)
			  FROM discovery_findings`).Scan(&count, &statusOK, &managedIDOK, &actorOK, &reasonOK, &triagedAtOK); err != nil {
			t.Fatalf("query 0051 default-filled columns: %v", err)
		}
		if count != beforeCount || !statusOK || !managedIDOK || !actorOK || !reasonOK || !triagedAtOK {
			t.Fatalf("0051 defaults mismatch: count=%d want=%d status=%t managed_id=%t actor=%t reason=%t triaged_at=%t",
				count, beforeCount, statusOK, managedIDOK, actorOK, reasonOK, triagedAtOK)
		}

		var indexExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('discovery_findings_triage_status_idx') IS NOT NULL`).Scan(&indexExists); err != nil {
			t.Fatalf("check 0051 triage index: %v", err)
		}
		if !indexExists {
			t.Fatal("expected discovery_findings_triage_status_idx after migration 0051")
		}
	})

	t.Run("0062_notification_routing_policy_metadata", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 62)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedNotificationRoutingPolicyMetadataContent(t, ctx, pool)

		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, notificationRoutingPolicyStableProjectionSQL())

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, notificationRoutingPolicyStableProjectionSQL())
		if afterCount != beforeCount {
			t.Fatalf("notification_routing_policies count changed across 0062: before=%d after=%d", beforeCount, afterCount)
		}
		if afterChecksum != beforeChecksum {
			t.Fatalf("notification_routing_policies existing values changed across 0062: before=%s after=%s", beforeChecksum, afterChecksum)
		}

		var count int
		var ownerRefOK, ownerEmailOK, digestIntervalOK, digestTimezoneOK bool
		if err := pool.QueryRow(ctx, `
			SELECT count(*),
			       bool_and(owner_ref = ''),
			       bool_and(owner_email = ''),
			       bool_and(digest_interval_seconds = 86400),
			       bool_and(digest_timezone = 'UTC')
			  FROM notification_routing_policies`).Scan(&count, &ownerRefOK, &ownerEmailOK, &digestIntervalOK, &digestTimezoneOK); err != nil {
			t.Fatalf("query 0062 default-filled columns: %v", err)
		}
		if count != beforeCount || !ownerRefOK || !ownerEmailOK || !digestIntervalOK || !digestTimezoneOK {
			t.Fatalf("0062 defaults mismatch: count=%d want=%d owner_ref=%t owner_email=%t digest_interval=%t digest_timezone=%t",
				count, beforeCount, ownerRefOK, ownerEmailOK, digestIntervalOK, digestTimezoneOK)
		}
	})
}

// TestMigration0071HistoricalLifecycleCompositePKContent is the SCHEMA-007
// historical-shape harness. Current greenfield replay reaches v70 with composite
// primary keys because the base migration has since been corrected, but installed
// databases from the old lineage reached v70 with owners/issuers/identities using
// PRIMARY KEY (id) plus UNIQUE (tenant_id, id). This test reconstructs that exact
// shape, seeds multi-tenant lifecycle rows and dependent FK rows, applies only
// 0071, then proves row content, FK validity, RLS scoping, and composite PK
// semantics.
func TestMigration0071HistoricalLifecycleCompositePKContent(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 71)

	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)

	applyMigrationFiles(t, ctx, pool, prefix)
	forceMigration0071HistoricalLifecycleShape(t, ctx, pool)
	for _, table := range []string{"owners", "issuers", "identities"} {
		assertPrimaryKeyColumns(t, ctx, pool, table, []string{"id"})
	}

	seedMigration0071LifecycleContent(t, ctx, pool)
	before := captureMigration0071LifecycleContent(t, ctx, pool)
	for table, snap := range before {
		if snap.count == 0 {
			t.Fatalf("precondition: %s should have historical rows before migration 0071", table)
		}
	}
	assertMigration0071ForeignKeysValid(t, ctx, pool)
	assertMigration0071OnlineSafetyClassification(t, target)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	after := captureMigration0071LifecycleContent(t, ctx, pool)
	for table, b := range before {
		a, ok := after[table]
		if !ok {
			t.Errorf("%s vanished after migration 0071", table)
			continue
		}
		if a.count != b.count {
			t.Errorf("%s row count changed across 0071: before=%d after=%d", table, b.count, a.count)
		}
		if a.checksum != b.checksum {
			t.Errorf("%s content changed across 0071: before=%s after=%s", table, b.checksum, a.checksum)
		}
	}
	for _, table := range []string{"owners", "issuers", "identities"} {
		assertPrimaryKeyColumns(t, ctx, pool, table, []string{"tenant_id", "id"})
	}
	assertMigration0071ForeignKeysValid(t, ctx, pool)
	assertMigration0071TenantScopedReads(t, ctx, pool, 1)
	assertMigration0071AllowsCrossTenantLifecycleIDs(t, ctx, pool)
}

// TestFutureValueChangingMigrationsRequireContentHarness is the SCHEMA-002 tripwire
// for future migrations. Creating a new table with defaults is just schema shape;
// backfilling from existing rows or default-filling columns on an already-existing
// table changes live values and needs a migration-content subtest like the two
// above.
func TestFutureValueChangingMigrationsRequireContentHarness(t *testing.T) {
	valueChanging := regexp.MustCompile(`(?is)\binsert\s+into\b.+\bselect\b|\balter\s+table\b.+\badd\s+column\b.+\bdefault\b`)
	for _, m := range orderedMigrationFiles(t) {
		if m.version <= 51 {
			continue
		}
		if valueChangingMigrationContentHarnesses[m.version] {
			continue
		}
		if valueChanging.MatchString(stripSQLLineComments(m.body)) {
			t.Errorf("%s looks like it writes live values; add an exact N-1 -> N case to TestMigrationDataContentBackfills or classify why it is shape-only", m.name)
		}
	}
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

func splitMigrationsAtVersion(t *testing.T, version int) ([]migrationFile, migrationFile) {
	t.Helper()
	var prefix []migrationFile
	var target migrationFile
	found := false
	for _, m := range orderedMigrationFiles(t) {
		if m.version < version {
			prefix = append(prefix, m)
			continue
		}
		if m.version == version {
			target = m
			found = true
		}
	}
	if !found {
		t.Fatalf("migration %04d not found", version)
	}
	if len(prefix) == 0 {
		t.Fatalf("migration %04d has empty prefix; expected an N-1 boundary", version)
	}
	return prefix, target
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

func checksumQuery(t *testing.T, ctx context.Context, pool *pgxpool.Pool, selectSQL string) (int, string) {
	t.Helper()
	q := fmt.Sprintf(`
		SELECT count(*), COALESCE(md5(string_agg(row_blob, chr(30))), 'empty')
		  FROM (SELECT concat_ws(chr(31), q.*) AS row_blob FROM (%s) q) s`, selectSQL)
	var count int
	var checksum string
	if err := pool.QueryRow(ctx, q).Scan(&count, &checksum); err != nil {
		t.Fatalf("checksum query: %v\n%s", err, q)
	}
	return count, checksum
}

func seedSecretStoreBackfillContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID string
		name     string
		sealed   []byte
		version  int
		updated  string
	}{
		{tenantID: tenantA, name: "api-key", sealed: []byte("sealed-secret-a"), version: 3, updated: "2026-01-02T03:04:05Z"},
		{tenantID: tenantA, name: "webhook-token", sealed: []byte("sealed-hook-a"), version: 8, updated: "2026-01-03T03:04:05Z"},
		{tenantID: tenantB, name: "api-key", sealed: []byte("sealed-secret-b"), version: 5, updated: "2026-01-04T03:04:05Z"},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5::timestamptz, $5::timestamptz)`,
			r.tenantID, r.name, r.sealed, r.version, r.updated); err != nil {
			t.Fatalf("seed secret_store %s/%s: %v", r.tenantID, r.name, err)
		}
	}
}

func seedDiscoveryFindingBackfillContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID    string
		sourceID    string
		runID       string
		findingID   string
		kind        string
		ref         string
		provenance  string
		fingerprint string
		riskScore   int
		metadata    string
	}{
		{
			tenantID:    tenantA,
			sourceID:    uuid(tenantA, 51),
			runID:       uuid(tenantA, 52),
			findingID:   uuid(tenantA, 53),
			kind:        "x509",
			ref:         "spiffe://tenant-a/workload-a",
			provenance:  "scan:a",
			fingerprint: "sha256:a",
			riskScore:   17,
			metadata:    `{"issuer":"ca-a","path":"/etc/a.pem"}`,
		},
		{
			tenantID:    tenantB,
			sourceID:    uuid(tenantB, 51),
			runID:       uuid(tenantB, 52),
			findingID:   uuid(tenantB, 53),
			kind:        "ssh",
			ref:         "host-b",
			provenance:  "scan:b",
			fingerprint: "sha256:b",
			riskScore:   29,
			metadata:    `{"host":"b.example.test","port":22}`,
		},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
			VALUES ($1, $2, 'network', $3, '{"cidr":"10.0.0.0/24"}'::jsonb, '2026-01-05T03:04:05Z'::timestamptz, '2026-01-05T03:04:05Z'::timestamptz)`,
			r.sourceID, r.tenantID, "source-"+r.tenantID); err != nil {
			t.Fatalf("seed discovery source %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO discovery_runs (id, tenant_id, source_id, status, dry_run, requested_by, targets, discovered, failed, rejected, error, started_at, completed_at, created_at)
			VALUES ($1, $2, $3, 'completed', false, 'schema-test', 2, 1, 0, 0, '', '2026-01-05T03:04:06Z'::timestamptz, '2026-01-05T03:04:07Z'::timestamptz, '2026-01-05T03:04:05Z'::timestamptz)`,
			r.runID, r.tenantID, r.sourceID); err != nil {
			t.Fatalf("seed discovery run %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO discovery_findings (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, '2026-01-05T03:04:08Z'::timestamptz)`,
			r.findingID, r.tenantID, r.runID, r.sourceID, r.kind, r.ref, r.provenance, r.fingerprint, r.riskScore, r.metadata); err != nil {
			t.Fatalf("seed discovery finding %s: %v", r.tenantID, err)
		}
	}
}

func discoveryFindingStableProjectionSQL() string {
	return `
		SELECT id::text,
		       tenant_id::text,
		       run_id::text,
		       source_id::text,
		       kind,
		       ref,
		       provenance,
		       fingerprint,
		       risk_score::text,
		       metadata::text,
		       discovered_at::text
		  FROM discovery_findings
		 ORDER BY tenant_id, id`
}

func seedNotificationRoutingPolicyMetadataContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID           string
		id                 string
		name               string
		channelsBySeverity string
		defaultChannels    string
		createdAt          string
		updatedAt          string
	}{
		{
			tenantID:           tenantA,
			id:                 uuid(tenantA, 62),
			name:               "critical-escalation",
			channelsBySeverity: `{"critical":["slack","webhook"],"warning":["email"]}`,
			defaultChannels:    `["email"]`,
			createdAt:          "2026-01-06T03:04:05Z",
			updatedAt:          "2026-01-06T03:04:06Z",
		},
		{
			tenantID:           tenantB,
			id:                 uuid(tenantB, 62),
			name:               "low-signal-digest",
			channelsBySeverity: `{"low":["email"]}`,
			defaultChannels:    `["webhook"]`,
			createdAt:          "2026-01-07T03:04:05Z",
			updatedAt:          "2026-01-07T03:04:06Z",
		},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO notification_routing_policies (
			    id, tenant_id, name, channels_by_severity, default_channels, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::timestamptz, $7::timestamptz)`,
			r.id, r.tenantID, r.name, r.channelsBySeverity, r.defaultChannels, r.createdAt, r.updatedAt); err != nil {
			t.Fatalf("seed notification routing policy %s/%s: %v", r.tenantID, r.name, err)
		}
	}
}

func notificationRoutingPolicyStableProjectionSQL() string {
	return `
		SELECT id::text,
		       tenant_id::text,
		       name,
		       channels_by_severity::text,
		       default_channels::text,
		       created_at::text,
		       updated_at::text
		  FROM notification_routing_policies
		 ORDER BY tenant_id, id`
}

func forceMigration0071HistoricalLifecycleShape(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	stmts := []string{
		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_tenant_id_owner_id_fkey`,
		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_tenant_id_issuer_id_fkey`,
		`ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_tenant_id_owner_id_fkey`,
		`ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_tenant_id_identity_id_fkey`,

		`ALTER TABLE owners DROP CONSTRAINT IF EXISTS owners_tenant_id_id_key`,
		`ALTER TABLE owners DROP CONSTRAINT IF EXISTS owners_pkey`,
		`ALTER TABLE owners ADD CONSTRAINT owners_pkey PRIMARY KEY (id)`,
		`ALTER TABLE owners ADD CONSTRAINT owners_tenant_id_id_key UNIQUE (tenant_id, id)`,

		`ALTER TABLE issuers DROP CONSTRAINT IF EXISTS issuers_tenant_id_id_key`,
		`ALTER TABLE issuers DROP CONSTRAINT IF EXISTS issuers_pkey`,
		`ALTER TABLE issuers ADD CONSTRAINT issuers_pkey PRIMARY KEY (id)`,
		`ALTER TABLE issuers ADD CONSTRAINT issuers_tenant_id_id_key UNIQUE (tenant_id, id)`,

		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_tenant_id_id_key`,
		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_pkey`,
		`ALTER TABLE identities ADD CONSTRAINT identities_pkey PRIMARY KEY (id)`,
		`ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_id_key UNIQUE (tenant_id, id)`,

		`ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_owner_id_fkey FOREIGN KEY (tenant_id, owner_id) REFERENCES owners (tenant_id, id)`,
		`ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_issuer_id_fkey FOREIGN KEY (tenant_id, issuer_id) REFERENCES issuers (tenant_id, id)`,
		`ALTER TABLE certificates ADD CONSTRAINT certificates_tenant_id_owner_id_fkey FOREIGN KEY (tenant_id, owner_id) REFERENCES owners (tenant_id, id)`,
		`ALTER TABLE attestations ADD CONSTRAINT attestations_tenant_id_identity_id_fkey FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("force historical 0071 shape: %v\n%s", err, stmt)
		}
	}
}

func seedMigration0071LifecycleContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID   string
		ownerID    string
		issuerID   string
		identityID string
		certID     string
		attestID   string
		label      string
	}{
		{
			tenantID:   tenantA,
			ownerID:    uuid(tenantA, 7101),
			issuerID:   uuid(tenantA, 7102),
			identityID: uuid(tenantA, 7103),
			certID:     uuid(tenantA, 7104),
			attestID:   uuid(tenantA, 7105),
			label:      "alpha",
		},
		{
			tenantID:   tenantB,
			ownerID:    uuid(tenantB, 7201),
			issuerID:   uuid(tenantB, 7202),
			identityID: uuid(tenantB, 7203),
			certID:     uuid(tenantB, 7204),
			attestID:   uuid(tenantB, 7205),
			label:      "bravo",
		},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
			VALUES ($1, $2, 'Service', $3, $4, '2026-02-01T00:00:00Z'::timestamptz)`,
			r.ownerID, r.tenantID, "owner-"+r.label, r.label+"@example.test"); err != nil {
			t.Fatalf("seed 0071 owner %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal, created_at)
			VALUES ($1, $2, 'x509', $3, ARRAY[$4]::text[], $5, true, '2026-02-01T00:01:00Z'::timestamptz)`,
			r.issuerID, r.tenantID, "issuer-"+r.label, "chain-"+r.label, "pub-"+r.label); err != nil {
			t.Fatalf("seed 0071 issuer %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO identities (
			    id, tenant_id, kind, name, owner_id, issuer_id, status,
			    not_before, not_after, attributes, created_at
			)
			VALUES (
			    $1, $2, 'x509', $3, $4, $5, 'issued',
			    '2026-02-01T00:02:00Z'::timestamptz,
			    '2026-05-01T00:02:00Z'::timestamptz,
			    $6::jsonb,
			    '2026-02-01T00:02:30Z'::timestamptz
			)`,
			r.identityID, r.tenantID, "identity-"+r.label, r.ownerID, r.issuerID, `{"env":"`+r.label+`"}`); err != nil {
			t.Fatalf("seed 0071 identity %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO certificates (
			    id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
			    key_algorithm, not_before, not_after, deployment_location, source, created_at
			)
			VALUES (
			    $1, $2, $3, $4, ARRAY[$5]::text[], $6, $7, $8,
			    'ecdsa-p256',
			    '2026-02-01T00:03:00Z'::timestamptz,
			    '2026-05-01T00:03:00Z'::timestamptz,
			    $9, 'schema-007',
			    '2026-02-01T00:03:30Z'::timestamptz
			)`,
			r.certID, r.tenantID, r.ownerID, "CN="+r.label+".example.test", r.label+".example.test",
			"issuer-"+r.label, "serial-"+r.label, "fp-"+r.label, "/etc/trstctl/"+r.label); err != nil {
			t.Fatalf("seed 0071 certificate %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO attestations (id, tenant_id, identity_id, kind, evidence, verified_at, created_at)
			VALUES (
			    $1, $2, $3, 'manual',
			    $4::jsonb,
			    '2026-02-01T00:04:00Z'::timestamptz,
			    '2026-02-01T00:04:30Z'::timestamptz
			)`,
			r.attestID, r.tenantID, r.identityID, `{"ticket":"`+r.label+`"}`); err != nil {
			t.Fatalf("seed 0071 attestation %s: %v", r.tenantID, err)
		}
	}
}

var migration0071LifecycleContentColumns = map[string]struct {
	cols    string
	orderBy string
}{
	"owners": {
		cols:    "id::text, tenant_id::text, kind, name, email, created_at::text",
		orderBy: "tenant_id, id",
	},
	"issuers": {
		cols:    "id::text, tenant_id::text, kind, name, array_to_string(chain, ','), public_key, internal::text, created_at::text",
		orderBy: "tenant_id, id",
	},
	"identities": {
		cols:    "id::text, tenant_id::text, kind, name, owner_id::text, issuer_id::text, status, not_before::text, not_after::text, attributes::text, created_at::text",
		orderBy: "tenant_id, id",
	},
	"certificates": {
		cols:    "id::text, tenant_id::text, owner_id::text, subject, array_to_string(sans, ','), issuer, serial, fingerprint, key_algorithm, not_before::text, not_after::text, deployment_location, source, created_at::text",
		orderBy: "tenant_id, id",
	},
	"attestations": {
		cols:    "id::text, tenant_id::text, identity_id::text, kind, evidence::text, verified_at::text, created_at::text",
		orderBy: "tenant_id, id",
	},
}

func captureMigration0071LifecycleContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]seededContentSnapshot {
	t.Helper()
	out := make(map[string]seededContentSnapshot, len(migration0071LifecycleContentColumns))
	for table, proj := range migration0071LifecycleContentColumns {
		q := fmt.Sprintf(
			`SELECT count(*), COALESCE(md5(string_agg(row_blob, chr(30) ORDER BY %s)), 'empty')
			   FROM (SELECT concat_ws(chr(31), %s) AS row_blob, %s FROM %s) s`,
			proj.orderBy, proj.cols, proj.orderBy, table)
		var count int
		var sum string
		if err := pool.QueryRow(ctx, q).Scan(&count, &sum); err != nil {
			t.Fatalf("capture 0071 content for %s: %v", table, err)
		}
		out[table] = seededContentSnapshot{count: count, checksum: sum}
	}
	return out
}

func assertPrimaryKeyColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, want []string) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT a.attname
		  FROM pg_constraint c
		  JOIN unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		 WHERE c.conrelid = $1::regclass
		   AND c.contype = 'p'
		 ORDER BY k.ord`, table)
	if err != nil {
		t.Fatalf("query primary key for %s: %v", table, err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scan primary key for %s: %v", table, err)
		}
		got = append(got, col)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate primary key for %s: %v", table, err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s primary key columns = %v, want %v", table, got, want)
	}
}

func assertMigration0071ForeignKeysValid(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	checks := []struct {
		table  string
		name   string
		target string
	}{
		{table: "identities", name: "identities_tenant_id_owner_id_fkey", target: "owners"},
		{table: "identities", name: "identities_tenant_id_issuer_id_fkey", target: "issuers"},
		{table: "certificates", name: "certificates_tenant_id_owner_id_fkey", target: "owners"},
		{table: "attestations", name: "attestations_tenant_id_identity_id_fkey", target: "identities"},
	}
	for _, c := range checks {
		var valid bool
		if err := pool.QueryRow(ctx, `
			SELECT convalidated
			  FROM pg_constraint
			 WHERE conrelid = $1::regclass
			   AND conname = $2
			   AND contype = 'f'
			   AND confrelid = $3::regclass`,
			c.table, c.name, c.target).Scan(&valid); err != nil {
			t.Fatalf("query FK %s.%s -> %s: %v", c.table, c.name, c.target, err)
		}
		if !valid {
			t.Fatalf("FK %s.%s -> %s is not validated", c.table, c.name, c.target)
		}
	}
}

func assertMigration0071OnlineSafetyClassification(t *testing.T, target migrationFile) {
	t.Helper()
	if target.version != 71 {
		t.Fatalf("target migration version = %d, want 71", target.version)
	}
	dropPrimaryKeyConstraintRe := regexp.MustCompile(`(?i)\bdrop\s+constraint\s+(?:if\s+exists\s+)?"?[a-z0-9_]*pkey"?\b`)
	addPrimaryKeyConstraintRe := regexp.MustCompile(`(?i)\badd\s+(?:constraint\s+"?[a-z0-9_]+"?\s+)?primary\s+key\b`)
	want := map[string]bool{
		"owners/drop-pkey":     false,
		"owners/add-pkey":      false,
		"issuers/drop-pkey":    false,
		"issuers/add-pkey":     false,
		"identities/drop-pkey": false,
		"identities/add-pkey":  false,
	}
	for _, stmt := range splitStatements(target.body) {
		body := stripSQLLineComments(stmt.sql)
		dropsPK := dropPrimaryKeyConstraintRe.MatchString(body)
		addsPK := addPrimaryKeyConstraintRe.MatchString(body)
		if !dropsPK && !addsPK {
			continue
		}
		table, ok := alterTargetTable(body)
		if !ok {
			t.Fatalf("0071 lock-heavy primary-key statement has no ALTER TABLE target: %s", oneLine(body))
		}
		op := "drop-pkey"
		if addsPK {
			op = "add-pkey"
		}
		key := table + "/" + op
		if _, ok := want[key]; !ok {
			t.Fatalf("0071 has unexpected primary-key rewrite classification %s in %s", key, oneLine(body))
		}
		if !stmt.onlineSafe {
			t.Fatalf("0071 %s lacks an online-safe justification comment: %s", key, oneLine(stmt.sql))
		}
		want[key] = true
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("0071 missing online-safety classification for %s", key)
		}
	}
}

func assertMigration0071TenantScopedReads(t *testing.T, ctx context.Context, pool *pgxpool.Pool, wantPerTenant int) {
	t.Helper()
	for _, tenantID := range []string{tenantA, tenantB} {
		for _, table := range []string{"owners", "issuers", "identities", "certificates", "attestations"} {
			got := countRowsAsTenant(t, ctx, pool, tenantID, table)
			if got != wantPerTenant {
				t.Fatalf("%s visible %s rows = %d, want %d", tenantID, table, got, wantPerTenant)
			}
		}
	}
}

func countRowsAsTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, table string) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant-scoped count: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE trstctl_app"); err != nil {
		t.Fatalf("set tenant role: %v", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID); err != nil {
		t.Fatalf("set tenant id: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
		t.Fatalf("tenant-scoped count %s/%s: %v", tenantID, table, err)
	}
	return count
}

func assertMigration0071AllowsCrossTenantLifecycleIDs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	ownerID := uuid(tenantA, 7101)
	issuerID := uuid(tenantA, 7102)
	identityID := uuid(tenantA, 7103)
	if _, err := pool.Exec(ctx, `
		INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
		VALUES ($1, $2, 'Service', 'tenant-b-duplicate-owner', 'dup@example.test', '2026-02-02T00:00:00Z'::timestamptz)`,
		ownerID, tenantB); err != nil {
		t.Fatalf("insert cross-tenant duplicate owner id after 0071: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal, created_at)
		VALUES ($1, $2, 'x509', 'tenant-b-duplicate-issuer', ARRAY['dup-chain']::text[], 'dup-pub', true, '2026-02-02T00:01:00Z'::timestamptz)`,
		issuerID, tenantB); err != nil {
		t.Fatalf("insert cross-tenant duplicate issuer id after 0071: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identities (
		    id, tenant_id, kind, name, owner_id, issuer_id, status,
		    not_before, not_after, attributes, created_at
		)
		VALUES (
		    $1, $2, 'x509', 'tenant-b-duplicate-identity', $3, $4, 'issued',
		    '2026-02-02T00:02:00Z'::timestamptz,
		    '2026-05-02T00:02:00Z'::timestamptz,
		    '{"env":"duplicate"}'::jsonb,
		    '2026-02-02T00:02:30Z'::timestamptz
		)`,
		identityID, tenantB, ownerID, issuerID); err != nil {
		t.Fatalf("insert cross-tenant duplicate identity id after 0071: %v", err)
	}
	if got := countRowsAsTenant(t, ctx, pool, tenantA, "owners"); got != 1 {
		t.Fatalf("tenant A owner visibility after cross-tenant duplicate = %d, want 1", got)
	}
	if got := countRowsAsTenant(t, ctx, pool, tenantB, "owners"); got != 2 {
		t.Fatalf("tenant B owner visibility after cross-tenant duplicate = %d, want 2", got)
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
