// SPDX-License-Identifier: MPL-2.0

package idemgc_test

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

	"trstctl.com/trstctl/internal/idemgc"
	"trstctl.com/trstctl/internal/store"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

var testDSN string

// TestMain starts one real PostgreSQL for the package, so the idempotency-key
// retention sweep is tested against the real schema, RLS, grants, and indexes.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-idemgc-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
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
	if _, err := s.SystemPool().Exec(ctx, `TRUNCATE tenants, idempotency_keys RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedCompleted(t *testing.T, s *store.Store, key string, completedAt time.Time) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`INSERT INTO idempotency_keys (tenant_id, key, status, result, completed_at)
		 VALUES ($1, $2, 'completed', $3, $4)`,
		tenantA, key, []byte(`{"ok":true}`), completedAt); err != nil {
		t.Fatalf("seed completed %s: %v", key, err)
	}
}

// TestIdempotencyPurgeBoundsTable locks SPINE-103: completed keys older than the
// retention window are reclaimed, while recent completed keys and pending claims
// survive. That keeps the table bounded without breaking AN-5 retry semantics
// inside the configured window.
func TestIdempotencyPurgeBoundsTable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	sweeper := idemgc.New(s, 24*time.Hour)

	old := time.Now().UTC().Add(-72 * time.Hour)
	recent := time.Now().UTC()
	for i := 0; i < 25; i++ {
		seedCompleted(t, s, fmt.Sprintf("old-%d", i), old)
		seedCompleted(t, s, fmt.Sprintf("recent-%d", i), recent)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO idempotency_keys (tenant_id, key, status)
		 VALUES ($1, 'pending-key', 'pending')`, tenantA); err != nil {
		t.Fatal(err)
	}

	before, err := sweeper.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before != 51 {
		t.Fatalf("seeded %d idempotency rows, want 51", before)
	}

	reclaimed, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if reclaimed != 25 {
		t.Fatalf("reclaimed %d rows, want 25 old completed keys", reclaimed)
	}
	after, err := sweeper.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != 26 {
		t.Fatalf("after sweep %d rows, want 26 (25 recent completed + 1 pending)", after)
	}

	var pending int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM idempotency_keys WHERE status = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending rows = %d, want 1 (in-flight idempotency claim must survive)", pending)
	}

	r2, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r2 != 0 {
		t.Fatalf("second sweep reclaimed %d, want 0", r2)
	}
}

// TestIdempotencyPurgeIndexUsed asserts the sweep predicate uses the partial
// completed_at index, so retention touches the old completed tail rather than
// scanning the full table as mutation volume grows.
func TestIdempotencyPurgeIndexUsed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	recent := time.Now().UTC()
	old := time.Now().UTC().Add(-72 * time.Hour)
	for i := 0; i < 2000; i++ {
		seedCompleted(t, s, fmt.Sprintf("recent-%d", i), recent)
	}
	for i := 0; i < 10; i++ {
		seedCompleted(t, s, fmt.Sprintf("old-%d", i), old)
	}
	if _, err := s.SystemPool().Exec(ctx, "ANALYZE idempotency_keys"); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	rows, err := s.SystemPool().Query(ctx,
		`EXPLAIN SELECT 1 FROM idempotency_keys WHERE completed_at IS NOT NULL AND completed_at < $1`, cutoff)
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
	if !strings.Contains(plan, "idempotency_keys_completed_at_idx") {
		t.Errorf("idempotency purge predicate does not use idempotency_keys_completed_at_idx; plan:\n%s", plan)
	}
}
