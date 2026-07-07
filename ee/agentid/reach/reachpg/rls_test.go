// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reachpg_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/ee/agentid/reach"
	corestore "trstctl.com/trstctl/internal/store"
)

// rls_test.go is the AN-1 RLS negative test for the reachability read path: the
// reachability engine builds its tenant graph THROUGH the core store's tenant-scoped list
// methods (under store.WithTenant / FORCE-d RLS), so a build for tenant B can NEVER read
// tenant A's inventory. This proves the graph query is tenant-scoped (a cross-tenant
// reachability read is denied) and is the substrate for the AGID-06 cross-tenant hazard the
// card calls out: never reuse a process-wide live graph for a mint decision; build per
// tenant under WithTenant.
//
// It is the SINGLE embedded-PostgreSQL test in the reach package family (kept small to
// conserve disk), mirroring the succession / delegation-store harness.

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL so RLS is exercised against the same FORCE-d
// row-level security the product runs under (no external service, no mocks).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-reach-pg")
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

func newStore(t *testing.T) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	s, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Reset the tenant-scoped inventory tables between tests (the package shares one DB).
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE tenants, owners, issuers, identities, deployment_targets RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedInventory seeds one tenant with an owner, an issuer, and an identity linking them,
// plus a deployment target — enough that graph.Build produces a non-empty graph (workload,
// issuer, credential, resource nodes) for that tenant.
func seedInventory(t *testing.T, s *corestore.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, corestore.Tenant{TenantID: tenantID, Name: "t-" + tenantID[:8]}); err != nil {
		t.Fatalf("UpsertTenant(%s): %v", tenantID, err)
	}
	ownerID := tenantID[:8] + "-0000-0000-0000-000000000001"
	if err := s.UpsertOwner(ctx, corestore.Owner{ID: ownerID, TenantID: tenantID, Kind: "service", Name: "svc-" + tenantID[:4]}); err != nil {
		t.Fatalf("UpsertOwner(%s): %v", tenantID, err)
	}
	idID := tenantID[:8] + "-0000-0000-0000-000000000002"
	if err := s.UpsertIdentity(ctx, corestore.Identity{
		ID: idID, TenantID: tenantID, Kind: "workload", Name: "cred-" + tenantID[:4],
		OwnerID: ownerID, Status: "active",
	}); err != nil {
		t.Fatalf("UpsertIdentity(%s): %v", tenantID, err)
	}
	if err := s.UpsertDeploymentTarget(ctx, corestore.DeploymentTarget{
		ID: tenantID[:8] + "-0000-0000-0000-000000000003", TenantID: tenantID, Name: "target-" + tenantID[:4], Type: "k8s",
	}); err != nil {
		t.Fatalf("UpsertDeploymentTarget(%s): %v", tenantID, err)
	}
}

// TestRLS_ReachabilityGraphReadIsTenantScoped is the AN-1 negative test: with ONLY tenant
// A's inventory seeded, the reachability engine's StoreGraphSource build for tenant A is
// non-empty, while a build for tenant B — which has no inventory — is EMPTY. The build for
// B cannot read A's rows because every list method runs under store.WithTenant with FORCE-d
// RLS scoping reads to B. This proves a cross-tenant reachability read is denied and the
// graph never spans tenants (the card's cross-tenant hazard is avoided by per-tenant build
// under WithTenant).
func TestRLS_ReachabilityGraphReadIsTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Seed ONLY tenant A.
	seedInventory(t, s, tenantA)
	// tenant B exists but has NO inventory.
	if err := s.UpsertTenant(ctx, corestore.Tenant{TenantID: tenantB, Name: "t-b"}); err != nil {
		t.Fatalf("UpsertTenant(B): %v", err)
	}

	src := reach.StoreGraphSource{Store: s} // nil Watermark ⇒ opaque per-tenant token

	// Tenant A's graph is populated (its seeded inventory produced nodes).
	gA, wmA, err := src.GraphForTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("GraphForTenant(A): %v", err)
	}
	if gA.Order() == 0 {
		t.Fatalf("tenant A graph is empty; expected seeded inventory to produce nodes")
	}
	if wmA == "" {
		t.Fatalf("tenant A watermark is empty")
	}

	// Tenant B's graph MUST be empty: RLS confines every list read the build issues to
	// tenant B, which has no inventory. If any of A's rows leaked across the tenant
	// boundary, B's graph would be non-empty — that is exactly what RLS prevents.
	gB, _, err := src.GraphForTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("GraphForTenant(B): %v", err)
	}
	if gB.Order() != 0 {
		t.Fatalf("tenant B graph has %d nodes; a cross-tenant reachability read must be denied (AN-1)", gB.Order())
	}

	// Drive the full engine for tenant B too: resolving any authority for B yields an empty
	// reachable set (nothing is reachable in an empty tenant graph), never A's assets.
	e := reach.NewEngine(src)
	set, _, err := e.Resolve(ctx, reach.AuthorityRequest{TenantID: tenantB, ResourceValues: []string{"target-1111"}})
	if err != nil {
		t.Fatalf("engine Resolve(B): %v", err)
	}
	if set.Cardinality != 0 {
		t.Fatalf("tenant B reachable set has %d nodes; must be empty (cross-tenant reach denied)", set.Cardinality)
	}
	if set.TenantID != tenantB {
		t.Fatalf("reachable set tenant = %q, want %q", set.TenantID, tenantB)
	}
}
