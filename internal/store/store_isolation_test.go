package store_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// This is part of the TENANT-007 package-level coverage for internal/store: until
// this sprint the store had no _test.go of its own and per-repo tenant isolation was
// proven only one layer up (internal/projections, internal/query). These tests drive
// the store repositories directly against the embedded PostgreSQL + FORCE-d RLS that
// the package's TestMain (offboard_test.go) stands up, so a single store method
// losing its tenant clause is caught here. It also exercises the ca_authorities
// composite self-FK (TENANT-006) and pins SystemPool as the named RLS-bypass
// accessor (TENANT-005). It reuses the shared newStore/tenantA/tenantB harness
// defined in offboard_test.go (same package).

func seedTwoTenants(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	for _, id := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: id, Name: "t-" + id[:8]}); err != nil {
			t.Fatalf("UpsertTenant(%s): %v", id, err)
		}
	}
}

// TestStoreAgentRepoIsolation proves the agents repository confines reads and lists to
// the caller's tenant: tenant B can neither Get nor List tenant A's agent.
func TestStoreAgentRepoIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const agentA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	if err := s.UpsertAgent(ctx, store.Agent{ID: agentA, TenantID: tenantA, Name: "edge-a", Status: "active"}); err != nil {
		t.Fatalf("UpsertAgent(A): %v", err)
	}

	if got, err := s.GetAgent(ctx, tenantA, agentA); err != nil || got.Name != "edge-a" {
		t.Fatalf("GetAgent(A) = (%+v, %v), want the seeded agent", got, err)
	}

	// Tenant B must NOT see tenant A's agent (RLS confines the read).
	if _, err := s.GetAgent(ctx, tenantB, agentA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetAgent(B, A's id) = %v, want ErrNoRows (cross-tenant read must be denied)", err)
	}

	bList, err := s.ListAgents(ctx, tenantB)
	if err != nil {
		t.Fatalf("ListAgents(B): %v", err)
	}
	if len(bList) != 0 {
		t.Fatalf("ListAgents(B) returned %d agents, want 0 (cross-tenant rows must be hidden)", len(bList))
	}
}

// TestStoreAgentUpsertOnConflictCannotCrossTenant covers the ON CONFLICT (id) path
// for a PK-on-id table (agents.id is the primary key). A tenant B upsert that reuses
// tenant A's agent id must NOT silently hijack or mutate tenant A's row: FORCE-d RLS
// rejects the write (the USING expression hides A's row from B, so the conflicting
// INSERT/UPDATE fails closed with SQLSTATE 42501) and tenant A's row is left intact.
// This proves a same-id collision across tenants cannot be used to overwrite another
// tenant's agent through the upsert path.
func TestStoreAgentUpsertOnConflictCannotCrossTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const sharedID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if err := s.UpsertAgent(ctx, store.Agent{ID: sharedID, TenantID: tenantA, Name: "a-name", Status: "active"}); err != nil {
		t.Fatalf("UpsertAgent(A): %v", err)
	}

	// Tenant B tries to upsert the same id: RLS must reject it (fail closed), so the
	// write cannot reach tenant A's row.
	if err := s.UpsertAgent(ctx, store.Agent{ID: sharedID, TenantID: tenantB, Name: "b-name", Status: "active"}); err == nil {
		t.Fatal("a cross-tenant id-collision upsert was accepted; RLS must reject it (fail closed)")
	}

	// Tenant A's row is unchanged, and tenant B has no such agent.
	aGot, err := s.GetAgent(ctx, tenantA, sharedID)
	if err != nil {
		t.Fatalf("GetAgent(A): %v", err)
	}
	if aGot.Name != "a-name" {
		t.Errorf("tenant A's agent name = %q, want %q (a cross-tenant upsert must not mutate A)", aGot.Name, "a-name")
	}
	if _, err := s.GetAgent(ctx, tenantB, sharedID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("tenant B unexpectedly has agent %s (err=%v); the rejected upsert must leave no B row", sharedID, err)
	}
}

// TestStoreCAAuthorityCrossTenantParentRejected is the TENANT-006 acceptance: the
// ca_authorities self-FK is now tenant-composite, so a CA in tenant B cannot point its
// parent_id at a CA row owned by tenant A. (Under RLS the parent is not even visible to
// tenant B, and the composite FK has no matching (tenant_id, id) row, so the insert
// fails.) A same-tenant parent still works.
func TestStoreCAAuthorityCrossTenantParentRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	rootA, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, CommonName: "root-a", Kind: "root", CertificatePEM: "PEM-A", MaxPathLen: -1,
	})
	if err != nil {
		t.Fatalf("InsertCAAuthority(A root): %v", err)
	}

	parent := rootA.ID
	if _, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantB, ParentID: &parent, CommonName: "evil-sub", Kind: "intermediate",
		CertificatePEM: "PEM-B", MaxPathLen: -1,
	}); err == nil {
		t.Fatal("a cross-tenant parent_id was accepted; the composite self-FK must reject it (TENANT-006)")
	}

	if _, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, ParentID: &parent, CommonName: "good-sub", Kind: "intermediate",
		CertificatePEM: "PEM-A2", MaxPathLen: -1,
	}); err != nil {
		t.Fatalf("same-tenant child insert failed: %v", err)
	}
}

// TestStoreSystemPoolIsTheNamedRLSBypassAccessor pins TENANT-005: the RLS-bypassing
// accessor is named SystemPool (greppable), and the deprecated Pool alias returns the
// same pool. A rename-away from SystemPool fails this test.
func TestStoreSystemPoolIsTheNamedRLSBypassAccessor(t *testing.T) {
	s := newStore(t)
	if s.SystemPool() == nil {
		t.Fatal("SystemPool() returned nil")
	}
	if s.SystemPool() != s.Pool() {
		t.Error("Pool() must remain an alias of SystemPool() during deprecation")
	}

	// Source guard: the accessor must be named SystemPool, so every RLS-bypassing access
	// site is greppable. (Reading our own source keeps the guard honest and non-vacuous.)
	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	if !strings.Contains(string(src), "func (s *Store) SystemPool()") {
		t.Error("store.go must define SystemPool() as the named RLS-bypass accessor (TENANT-005)")
	}
}
