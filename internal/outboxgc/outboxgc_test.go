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

	"trustctl.io/trustctl/internal/outboxgc"
	"trustctl.io/trustctl/internal/store"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

var testDSN string

// TestMain starts a single real PostgreSQL (downloaded, no external service) for
// the whole package, so the outbox retention sweep is integration-tested against
// the real schema, RLS, and indexes — never mocked. It shares the same stable
// binary cache as the rest of the suite.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trustctl-outboxgc-pg")
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
	if _, err := s.Pool().Exec(ctx, `TRUNCATE tenants, outbox RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedDelivered(t *testing.T, s *store.Store, key string, deliveredAt time.Time) {
	t.Helper()
	if _, err := s.Pool().Exec(context.Background(),
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, delivered_at)
		 VALUES ($1, 'issuance', $2, $3, 'delivered', $4)`,
		tenantA, []byte("p"), key, deliveredAt); err != nil {
		t.Fatalf("seed delivered %s: %v", key, err)
	}
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
	if _, err := s.Pool().Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status)
		 VALUES ($1, 'issuance', $2, 'pending-key', 'pending')`, tenantA, []byte("p")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx,
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
	if err := s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE status = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool().QueryRow(ctx,
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
	if _, err := s.Pool().Exec(ctx, "ANALYZE outbox"); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	rows, err := s.Pool().Query(ctx,
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
