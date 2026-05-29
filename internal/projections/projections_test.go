package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/projections"
	"certctl.io/certctl/internal/store"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts a single real PostgreSQL (downloaded, no external service) for
// the whole package; the spine is integration-tested against it, never mocked.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "certctl-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(os.TempDir() + "/certctl-pg-bin"). // stable cache across runs
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
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
	// Per-test isolation: the whole package shares one database, so reset the
	// read model and the orchestrator's state/outbox tables between tests.
	if _, err := s.Pool().Exec(ctx,
		`TRUNCATE tenants, idempotency_keys, outbox,
		          owners, issuers, identities, deployment_targets,
		          agents, policy_bindings, attestations, api_tokens
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func openLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	return log
}

func tenantRegistered(name string) []byte {
	b, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{name})
	return b
}

// TestRLSDeniesCrossTenantRead is the AN-1 acceptance: a tenant context cannot
// read another tenant's rows.
func TestRLSDeniesCrossTenantRead(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}

	var sawAll, sawOther int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&sawAll); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE tenant_id = $1", tenantB).Scan(&sawOther)
	}); err != nil {
		t.Fatalf("WithTenant: %v", err)
	}
	if sawAll != 1 {
		t.Errorf("tenant A sees %d rows, want 1 (RLS should hide other tenants)", sawAll)
	}
	if sawOther != 0 {
		t.Errorf("tenant A can see tenant B's row (%d); RLS must deny it", sawOther)
	}
}

func TestEventsProjectIntoReadModel(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	if _, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: tenantB, Data: tenantRegistered("Beta")}); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("project: %v", err)
	}

	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 2 {
		t.Fatalf("projected %d tenants, want 2", len(tenants))
	}
	byID := map[string]string{}
	for _, tn := range tenants {
		byID[tn.TenantID] = tn.Name
	}
	if byID[tenantA] != "Acme" || byID[tenantB] != "Beta" {
		t.Errorf("read model = %v, want Acme/Beta", byID)
	}
}

// TestRebuildReproducesState replays the log into a truncated read model and
// gets the same state (AN-2: the read model is a projection of the log).
func TestRebuildReproducesState(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	for _, tc := range []struct{ id, name string }{{tenantA, "Acme"}, {tenantB, "Beta"}} {
		if _, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: tc.id, Data: tenantRegistered(tc.name)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	before, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	after, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !sameTenants(before, after) {
		t.Errorf("rebuild changed state:\n before=%v\n after =%v", before, after)
	}
}

func sameTenants(a, b []store.Tenant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].TenantID != b[i].TenantID || a[i].Name != b[i].Name {
			return false
		}
	}
	return true
}
