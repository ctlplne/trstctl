// SPDX-License-Identifier: MPL-2.0

package outboxgc_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/store"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

var testDSN string

// TestMain starts a single real PostgreSQL (downloaded, no external service) for
// the whole package, so the outbox retention sweep is integration-tested against
// the real schema, RLS, and indexes — never mocked. It shares the same stable
// binary cache as the rest of the suite.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-outboxgc-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin"). // per-package, not a shared /tmp dir: parallel `go test ./...` packages race the file-by-file extraction into a shared BinariesPath
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE code_signing_operations, managed_key_operations, managed_keys,
		          tenants, outbox RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedDelivered(t *testing.T, s *store.Store, key string, deliveredAt time.Time) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, delivered_at)
		 VALUES ($1, 'issuance', $2, $3, 'delivered', $4)`,
		tenantA, []byte("p"), key, deliveredAt); err != nil {
		t.Fatalf("seed delivered %s: %v", key, err)
	}
}

func seedDeliveredID(t *testing.T, s *store.Store, key string, deliveredAt time.Time) int64 {
	t.Helper()
	var id int64
	if err := s.SystemPool().QueryRow(context.Background(),
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, delivered_at)
		 VALUES ($1, 'durable-command', $2, $3, 'delivered', $4)
		 RETURNING id`, tenantA, []byte("sealed-command"), key, deliveredAt).Scan(&id); err != nil {
		t.Fatalf("seed delivered %s: %v", key, err)
	}
	return id
}

// TestOutboxPurgeBoundsTable is the SPINE-003 acceptance: the retention sweep
// reclaims delivered outbox rows past the window, while pending and failed rows are
// preserved — so the outbox table stays bounded without dropping any undelivered
// effect (AN-6). It fails on the pre-fix tree, which never deleted a delivered row.
func TestOutboxPurgeBoundsTable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	sweeper := outboxgc.New(s, 24*time.Hour)

	old := time.Now().UTC().Add(-72 * time.Hour)
	recent := time.Now().UTC()
	for i := 0; i < 25; i++ {
		seedDelivered(t, s, fmt.Sprintf("old-%d", i), old)
		seedDelivered(t, s, fmt.Sprintf("recent-%d", i), recent)
	}
	// A pending (not-yet-delivered) row and a dead-lettered failed row must survive
	// any sweep — they are the dispatcher's work queue and the failure trail (AN-6).
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status)
		 VALUES ($1, 'issuance', $2, 'pending-key', 'pending')`, tenantA, []byte("p")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, attempts, last_error)
		 VALUES ($1, 'issuance', $2, 'failed-key', 'failed', 10, 'boom')`, tenantA, []byte("p")); err != nil {
		t.Fatal(err)
	}

	before, err := sweeper.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before != 52 {
		t.Fatalf("seeded %d outbox rows, want 52", before)
	}

	// A 24h retention reclaims the 72h-old delivered rows; recent + pending + failed survive.
	reclaimed, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if reclaimed != 25 {
		t.Fatalf("reclaimed %d rows, want 25 (the old delivered rows)", reclaimed)
	}
	after, err := sweeper.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != 27 {
		t.Fatalf("after sweep %d rows, want 27 (25 recent + pending + failed) — table must be bounded", after)
	}

	// The pending and failed rows specifically must still be there (AN-6: no
	// undelivered effect is ever dropped).
	var pending, failed int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE status = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE status = 'failed'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if pending != 1 || failed != 1 {
		t.Fatalf("pending=%d failed=%d, want 1 each (undelivered/failed rows must never be purged)", pending, failed)
	}

	// The sweep is idempotent: a second pass reclaims nothing (the bound holds).
	r2, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r2 != 0 {
		t.Fatalf("second sweep reclaimed %d, want 0", r2)
	}
}

// Lifecycle projections keep numeric outbox ids as historical evidence. They do
// not own delivered queue rows: otherwise an FK makes retention GC fail forever
// and the supposedly bounded outbox grows without limit.
func TestOutboxPurgeReclaimsCompletedManagedKeyAndCodeSigningCommands(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-72 * time.Hour)
	managedOutboxID := seedDeliveredID(t, s, "managed-key-completed", old)
	codeSignOutboxID := seedDeliveredID(t, s, "code-signing-completed", old)
	created := old.Add(-time.Minute)
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO managed_key_operations
		        (tenant_id, operation_id, provider, action, key_id, algorithm,
		         status, result_key_id, public_der, result_state, outbox_id,
		         created_at, updated_at)
		 VALUES ($1, 'managed-op-completed', 'aws-kms', 'generate', '', 'rsa-2048',
		         'completed', 'kms-key-1', $2, 'active', $3, $4, $5)`,
		tenantA, []byte("public-der"), managedOutboxID, created, old); err != nil {
		t.Fatalf("seed completed managed-key operation: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO code_signing_operations
		        (tenant_id, operation_id, idempotency_key, mode, request_hash,
		         sealed_command, status, response, cleanup_status,
		         command_outbox_id, created_at, updated_at)
		 VALUES ($1, 'codesign-op-completed', 'codesign-request-completed', 'key',
		         'request-hash', $2, 'completed', $3, 'not_required', $4, $5, $6)`,
		tenantA, []byte("sealed-sign-command"), []byte("signed-response"),
		codeSignOutboxID, created, old); err != nil {
		t.Fatalf("seed completed code-signing operation: %v", err)
	}

	sweeper := outboxgc.New(s, 24*time.Hour)
	reclaimed, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep with completed lifecycle references: %v", err)
	}
	if reclaimed != 2 {
		t.Fatalf("reclaimed %d rows, want both completed command rows", reclaimed)
	}
	if remaining, err := sweeper.Count(ctx); err != nil || remaining != 0 {
		t.Fatalf("bounded outbox count=(%d, %v), want (0, nil)", remaining, err)
	}

	var managedRows, codeSignRows int
	var retainedManagedID, retainedCodeSignID int64
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*), COALESCE(max(outbox_id), 0)
		   FROM managed_key_operations WHERE tenant_id = $1 AND operation_id = 'managed-op-completed'`,
		tenantA).Scan(&managedRows, &retainedManagedID); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*), COALESCE(max(command_outbox_id), 0)
		   FROM code_signing_operations WHERE tenant_id = $1 AND operation_id = 'codesign-op-completed'`,
		tenantA).Scan(&codeSignRows, &retainedCodeSignID); err != nil {
		t.Fatal(err)
	}
	if managedRows != 1 || codeSignRows != 1 || retainedManagedID != managedOutboxID || retainedCodeSignID != codeSignOutboxID {
		t.Fatalf("historical projections changed: managed=(rows:%d id:%d) codesign=(rows:%d id:%d)",
			managedRows, retainedManagedID, codeSignRows, retainedCodeSignID)
	}
}

// TestOutboxPurgeIndexUsed asserts the sweep's predicate uses the partial
// delivered_at index (SPINE-003 / migration 0020) rather than a sequential scan, so
// reclamation stays cheap as the table grows. The table is dominated by recently-
// delivered rows with a small eligible old tail — the steady state under retention.
func TestOutboxPurgeIndexUsed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	recent := time.Now().UTC()
	old := time.Now().UTC().Add(-72 * time.Hour)
	for i := 0; i < 2000; i++ {
		seedDelivered(t, s, fmt.Sprintf("recent-%d", i), recent)
	}
	for i := 0; i < 10; i++ {
		seedDelivered(t, s, fmt.Sprintf("old-%d", i), old)
	}
	if _, err := s.SystemPool().Exec(ctx, "ANALYZE outbox"); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	rows, err := s.SystemPool().Query(ctx,
		`EXPLAIN SELECT 1 FROM outbox WHERE status = 'delivered' AND delivered_at IS NOT NULL AND delivered_at < $1`, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan += line + "\n"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "outbox_delivered_at_idx") {
		t.Errorf("outbox purge predicate does not use outbox_delivered_at_idx; plan:\n%s", plan)
	}
}
