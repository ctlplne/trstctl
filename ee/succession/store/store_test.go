// SPDX-License-Identifier: LicenseRef-trstctl-EE

package store_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	corestore "trstctl.com/trstctl/internal/store"

	pcasstore "trstctl.com/trstctl/ee/succession/store"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL for the PCAS store integration
// tests (no external service, no mocks) so RLS is exercised against the same
// FORCE-d row-level security the product runs under.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-pcas-store-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(port).
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

// freePort returns an ephemeral TCP port as uint32, the type embedded-postgres
// takes, so no narrowing conversion happens at the call site. The listener's
// port is a Go int; it is range-checked here against the TCP port space before
// the (now provably in-range) conversion.
func freePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p < 0 || p > math.MaxUint16 {
		panic(fmt.Sprintf("listener returned out-of-range TCP port %d", p))
	}
	return uint32(p)
}

func newRepo(t *testing.T) *pcasstore.Repo {
	t.Helper()
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pcasstore.New(cs)
}

func rec(identity string, epoch uint64) pcasstore.Record {
	return pcasstore.Record{
		IdentityID: identity, Epoch: epoch, PredecessorEpoch: epoch - 1,
		PredecessorAlg: "ECDSA-P256", SuccessorAlg: "Ed25519",
		SuccessorPub: []byte{byte(epoch & 0xFF)}, Encoded: []byte{0xAB, byte(epoch & 0xFF)},
	}
}

// TestRLS_CrossTenantDenied: a record written under one tenant is invisible to
// another; row-level security denies cross-tenant reads (PCAS-claim-7 / INV-5 RLS).
func TestRLS_CrossTenantDenied(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	const id = "spiffe://a.example/db"

	if err := repo.AppendRecord(ctx, tenantA, rec(id, 1)); err != nil {
		t.Fatalf("append (tenantA): %v", err)
	}
	if err := repo.UpsertHighWater(ctx, tenantA, id, 1); err != nil {
		t.Fatalf("high-water (tenantA): %v", err)
	}

	chainA, err := repo.FetchChain(ctx, tenantA, id)
	if err != nil {
		t.Fatalf("fetch (tenantA): %v", err)
	}
	if len(chainA) != 1 {
		t.Fatalf("tenantA chain len = %d, want 1", len(chainA))
	}

	// tenantB must not see tenantA's record or high-water.
	chainB, err := repo.FetchChain(ctx, tenantB, id)
	if err != nil {
		t.Fatalf("fetch (tenantB): %v", err)
	}
	if len(chainB) != 0 {
		t.Fatalf("cross-tenant read leaked %d rows", len(chainB))
	}
	if _, found, err := repo.GetHighWater(ctx, tenantB, id); err != nil || found {
		t.Fatalf("cross-tenant high-water leaked (found=%v err=%v)", found, err)
	}
}

// TestSuccessionChain_OrderedAndComplete: FetchChain returns records ordered and
// complete by epoch even when appended out of order.
func TestSuccessionChain_OrderedAndComplete(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	const id = "spiffe://a.example/api"

	for _, e := range []uint64{3, 1, 2} {
		if err := repo.AppendRecord(ctx, tenantA, rec(id, e)); err != nil {
			t.Fatalf("append epoch %d: %v", e, err)
		}
	}
	chain, err := repo.FetchChain(ctx, tenantA, id)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain len = %d, want 3", len(chain))
	}
	for i, want := range []uint64{1, 2, 3} {
		if chain[i].Epoch != want {
			t.Fatalf("chain[%d].Epoch = %d, want %d (not ordered)", i, chain[i].Epoch, want)
		}
	}
}

// TestHighWater_MonotonicUpsert: the serving high-water advances only upward; an
// equal or lower epoch is rejected and leaves the stored value unchanged.
func TestHighWater_MonotonicUpsert(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	const id = "spiffe://a.example/hw"

	if err := repo.UpsertHighWater(ctx, tenantA, id, 1); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	if err := repo.UpsertHighWater(ctx, tenantA, id, 3); err != nil {
		t.Fatalf("upsert 3: %v", err)
	}
	// Regression (2 <= 3) must be rejected.
	if err := repo.UpsertHighWater(ctx, tenantA, id, 2); !errors.Is(err, pcasstore.ErrHighWaterRegression) {
		t.Fatalf("upsert 2: got %v, want ErrHighWaterRegression", err)
	}
	// Equal (3) must be rejected too.
	if err := repo.UpsertHighWater(ctx, tenantA, id, 3); !errors.Is(err, pcasstore.ErrHighWaterRegression) {
		t.Fatalf("upsert 3 again: got %v, want ErrHighWaterRegression", err)
	}
	got, found, err := repo.GetHighWater(ctx, tenantA, id)
	if err != nil || !found {
		t.Fatalf("get high-water: found=%v err=%v", found, err)
	}
	if got != 3 {
		t.Fatalf("high-water = %d, want 3 (regression must not lower it)", got)
	}
}

// TestCoreOnly_AppliesZeroPCASMigrations: on a fresh database a core store with
// NO extra-migrations seam creates no PCAS tables; registering the seam is what
// adds them (G6 — the core-only build applies zero PCAS migrations).
func TestCoreOnly_AppliesZeroPCASMigrations(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS pcas_coreonly")
	if _, err := admin.Exec(ctx, "CREATE DATABASE pcas_coreonly"); err != nil {
		t.Fatalf("create db: %v", err)
	}
	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/pcas_coreonly"

	// Core store WITHOUT the seam: no PCAS tables.
	core, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	if err := core.Migrate(ctx); err != nil {
		t.Fatalf("core migrate: %v", err)
	}
	if reg := regclass(t, core, "succession_records"); reg != nil {
		t.Fatalf("core-only migrate created a PCAS table: %q", *reg)
	}

	// Same database WITH the seam: PCAS tables now present.
	seamed, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("seam open: %v", err)
	}
	seamed.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := seamed.Migrate(ctx); err != nil {
		t.Fatalf("seam migrate: %v", err)
	}
	if reg := regclass(t, seamed, "succession_records"); reg == nil {
		t.Fatal("seam did not create the PCAS table")
	}
}

func regclass(t *testing.T, s *corestore.Store, table string) *string {
	t.Helper()
	var reg *string
	if err := s.SystemPool().QueryRow(context.Background(),
		"SELECT to_regclass('public.'||$1)::text", table).Scan(&reg); err != nil {
		t.Fatalf("to_regclass(%s): %v", table, err)
	}
	return reg
}
