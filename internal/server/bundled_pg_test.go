package server

import (
	"context"
	"net"
	"testing"

	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/store"
)

// freeTCPPort returns an unused loopback port so the bundled instance does not
// collide with anything (and avoids the fixed 5432 default in CI).
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// TestBundledPostgresServes is R4.5's acceptance for the delivered bundled eval
// datastore: CERTCTL_POSTGRES_MODE=bundled actually serves. It starts the embedded
// single-node Postgres, opens the store against the returned DSN, migrates, and
// performs a real tenant-scoped insert+read — which exercises the SET LOCAL ROLE
// certctl_app + RLS path, so it only passes if bundled mode genuinely serves the
// full schema (not a silently-failing default).
func TestBundledPostgresServes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	dsn, stop, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: freeTCPPort(t)})
	if err != nil {
		t.Fatalf("start bundled postgres: %v", err)
	}
	defer func() { _ = stop() }()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store against bundled postgres: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate bundled postgres: %v", err)
	}

	// After migrate there is nothing pending — the bundled database actually served
	// the schema.
	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("pending migrations after migrate = %v, want none (bundled did not fully apply)", pending)
	}

	// A tenant-scoped insert+read proves end-to-end serving under RLS: the store
	// drops to the non-superuser certctl_app role per transaction, so this fails if
	// the role or schema were not created.
	const tenant = "11111111-1111-1111-1111-111111111111"
	if err := st.AddWatchedDomain(ctx, tenant, "example.com"); err != nil {
		t.Fatalf("tenant-scoped insert against bundled postgres: %v", err)
	}
	got, err := st.ListWatchedDomains(ctx, tenant)
	if err != nil {
		t.Fatalf("tenant-scoped read against bundled postgres: %v", err)
	}
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("watched domains = %v, want [example.com]", got)
	}
}
