// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestAgentProjectionConcurrentReplayMatchesThePrimaryKey is the live g32
// regression guard. The request path projects an appended heartbeat immediately
// for read-after-write behavior while the durable projector may consume the same
// event at the same time. Both inserts must converge on the tenant-scoped agent
// primary key instead of occasionally surfacing either uniqueness constraint.
func TestAgentProjectionConcurrentReplayMatchesThePrimaryKey(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)
	for i := 0; i < 32; i++ {
		id := fmt.Sprintf("90000000-0000-0000-0000-%012x", i)
		row := store.Agent{ID: id, TenantID: tenantA, Name: "concurrent-agent", Status: "active", Version: "g32"}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.UpsertAgent(ctx, row)
		}()
		go func() {
			defer wg.Done()
			<-start
			errs <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.ApplyAgentCertRenewedTx(ctx, tx, row)
			})
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent projection %d: %v", i, err)
			}
		}
	}
}

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

	bList, err := s.ListAgentsPage(ctx, tenantB, nil, store.ZeroUUID, 20)
	if err != nil {
		t.Fatalf("ListAgentsPage(B): %v", err)
	}
	if len(bList) != 0 {
		t.Fatalf("ListAgentsPage(B) returned %d agents, want 0 (cross-tenant rows must be hidden)", len(bList))
	}
}

// TestStoreAgentIDsAreTenantScoped proves the composite primary key and FORCE RLS
// agree on identity: two tenants may use the same UUID without colliding, and each
// tenant reads only its own independent row.
func TestStoreAgentIDsAreTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const sharedID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if err := s.UpsertAgent(ctx, store.Agent{ID: sharedID, TenantID: tenantA, Name: "a-name", Status: "active"}); err != nil {
		t.Fatalf("UpsertAgent(A): %v", err)
	}

	if err := s.UpsertAgent(ctx, store.Agent{ID: sharedID, TenantID: tenantB, Name: "b-name", Status: "active"}); err != nil {
		t.Fatalf("UpsertAgent(B, same tenant-scoped id): %v", err)
	}

	// Tenant A's row is unchanged and tenant B sees only its own row.
	aGot, err := s.GetAgent(ctx, tenantA, sharedID)
	if err != nil {
		t.Fatalf("GetAgent(A): %v", err)
	}
	if aGot.Name != "a-name" {
		t.Errorf("tenant A's agent name = %q, want %q (a cross-tenant upsert must not mutate A)", aGot.Name, "a-name")
	}
	bGot, err := s.GetAgent(ctx, tenantB, sharedID)
	if err != nil {
		t.Fatalf("GetAgent(B): %v", err)
	}
	if bGot.Name != "b-name" {
		t.Errorf("tenant B's agent name = %q, want %q", bGot.Name, "b-name")
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
		TenantID: tenantA, CommonName: "root-a", Kind: "root", CertificatePEM: "PEM-A", Serial: "A-ROOT", MaxPathLen: -1,
	})
	if err != nil {
		t.Fatalf("InsertCAAuthority(A root): %v", err)
	}

	parent := rootA.ID
	if _, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantB, ParentID: &parent, CommonName: "evil-sub", Kind: "intermediate",
		CertificatePEM: "PEM-B", Serial: "B-EVIL-SUB", MaxPathLen: -1,
	}); err == nil {
		t.Fatal("a cross-tenant parent_id was accepted; the composite self-FK must reject it (TENANT-006)")
	}

	if _, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, ParentID: &parent, CommonName: "good-sub", Kind: "intermediate",
		CertificatePEM: "PEM-A2", Serial: "A-GOOD-SUB", MaxPathLen: -1,
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
	if s.SystemPool() != s.Pool() { //nolint:staticcheck // This test pins the deprecated Pool alias during its compatibility window.
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

// TestSystemPoolProductionUseInventory pins TENANT-STRENGTH-001's "named and
// rare" rule: production RLS-bypass call sites must stay greppable and consciously
// reviewed. ELI5: the master key to walk around tenant fences exists, but every
// place it is used has to stay on this tiny written list.
func TestSystemPoolProductionUseInventory(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	approved := map[string]int{
		// J2: one full-restore transaction replaces cross-tenant independent
		// command state only after the artifact and event rebuild validate. The
		// transaction never returns tenant payloads; every restored receiver row
		// is matched to its exact event-derived tenant/job identity before commit.
		"internal/backup/postgres_state.go":       1,
		"internal/cli/doctor/probes_isolation.go": 1,
		// A6 adds a third: the FABRIC-1 sweep over agent-claimable work that no
		// agent has taken. It is cross-tenant for the same reason DUR-2 is —
		// "is the fabric moving" is a whole-system question one tenant's view
		// cannot answer — and it reads ages, kinds and the role demand, never a
		// payload, a credential or a tenant id.
		"internal/cli/doctor/probes_ops.go": 3,
		"internal/store/rls_inventory.go":   3,
		"internal/idemgc/idemgc.go":         2,
		"internal/perf/live.go":             1,
		"internal/orchestrator/outbox.go":   2,
		"internal/outboxgc/outboxgc.go":     2,
		// The readiness "db" check moved to the store's dedicated probe pool
		// (ProbePing, DP2-054), so server.go no longer touches SystemPool.
		// The leader enumerates tenant IDs for renewal, then reads rows under RLS.
		// Startup separately asks one deployment-wide boolean about legacy
		// rollback ordering; that query exposes no tenant IDs or receipt data.
		"internal/store/connector_lifecycle.go": 2,
		// Event-derived stop maintenance enumerates at most 100 tenant IDs.
		// The scheduler then re-enters each tenant's RLS context to validate
		// immutable transitions and cancel only that tenant's idle work.
		"internal/store/identity_work_stop.go": 1,
		"internal/store/lifecycle.go":          1,
		// AUD-109: startup/rebuild must compare every tenant's terminal
		// secret-sync SQL receipt with retained event history before any worker
		// can run, so that inventory is deliberately deployment-wide and exposes
		// only closed delivery metadata, never payload bytes. The second use pins
		// one PostgreSQL session while it holds the tenant+job terminal-choice
		// advisory lock; tenant reads and projection writes inside the callback
		// still use their normal RLS-scoped transactions.
		"internal/store/secret_sync_job.go": 2,
		// J2: the receiver recovery red light is one deployment singleton, not a
		// tenant row. Full restore must fence, authorize, and read it across every
		// tenant at once or one lane could perform I/O while another is still
		// rebuilding. The three calls expose only a boolean/reason from that fixed
		// closed row; they never read a tenant ID, command, or sealed payload.
		"internal/store/secret_sync_recovery.go": 3,
		// D2: the verification scheduler's leader enumerator — "which tenants
		// have endpoints worth re-probing" — has the same shape as the expiry
		// enumerator above and the same justification: a scheduler must know
		// who has work before it can enter any tenant's scope. It reads tenant
		// ids ONLY; every endpoint row is then loaded under that tenant's RLS
		// context by ListEndpointVerifications.
		"internal/store/endpoint_verification.go": 1,
		// R1: the leader first asks which tenant IDs own active public
		// certificates, then re-enters each tenant's RLS context for certificate
		// details. The second call reads PostgreSQL's clock so every replica uses
		// one scheduling bucket; it contains no tenant data at all.
		"internal/store/revocation_health.go": 2,
		// H5: the CA calendar's leader enumerator — "which tenants operate a CA
		// authority with a known expiry" — mirrors the expiry-alert enumerator in
		// lifecycle.go. It reads tenant ids only; the authority rows themselves are
		// then loaded under each tenant's RLS context.
		"internal/store/ca_horizon.go": 1,
		// A1: two leader-side job-ledger operations. The lapsed-lease sweep must
		// cross tenants because a dead agent leaves work in whatever tenant it
		// served, and it touches lease bookkeeping only. The queue-depth read is
		// process-wide by construction — it aggregates counts and one timestamp per
		// destination for the operations surface and returns no tenant id, payload
		// or credential. A3 adds a third: process-wide credential-redemption
		// health (how many redeemed credentials are live right now, and how long
		// the oldest has been held). That number is only meaningful across the
		// whole process — one tenant's view cannot tell an operator the fabric is
		// holding material past a lapsed lease — and like its siblings it returns
		// two counts and one timestamp, never a tenant, agent, job, reference
		// name or value.
		"internal/store/agent_jobs.go": 3,
		// A1: two process-wide reads of the signed receipt ledger for the same
		// operations surface. "Is the evidence on this control plane intact" is
		// a question about the deployment, not about one tenant's certificates —
		// a per-tenant view would show a clean page to nine tenants while the
		// tenth's agents are being refused. What crosses the boundary is two
		// counts, one timestamp, and one refusal reason from this server's own
		// closed set; no tenant, agent, job, statement or signature.
		"internal/store/agent_job_receipts.go": 2,
		// J2: CREATE DATABASE and DROP DATABASE for the restore drill's
		// throwaway target. Neither statement has a tenant scope to be given —
		// they are server-level DDL, and PostgreSQL will not run either inside a
		// transaction or against a pool bound to a row-level policy.
		//
		// Nothing tenant-owned crosses here. The name is generated
		// (trstctl_restore_drill_<nano>), the database exists only for the
		// length of the drill, and it is dropped WITH (FORCE) on every path
		// including the failure ones. The restore that populates it runs through
		// the ordinary tenant-scoped path against that database, so the drill
		// proves the production restore rather than a privileged shortcut.
		"internal/server/drill.go": 2,
		// VDEC (part of the core since 2026-09-20; this inventory did not scan
		// ee/ before): the retirement projection's standalone Reset and Apply
		// entry points open one system-pool transaction each. Reset is the
		// full-replay wipe of every tenant's derived retirement view, cross-tenant
		// by design, before exact tenant-bound events repopulate it. Apply drives
		// ApplyTx for one event: every statement it runs is scoped by that
		// event's own tenant_id (the payload's tenant must equal the event's or
		// the event is refused), the same rows the core projector writes through
		// ApplyTx inside the tenant's RLS transaction. Reads go through Fetch,
		// which enters the tenant's RLS context; nothing tenant-owned is returned
		// to a caller from the system pool.
		"internal/decommission/retirement/projection.go": 2,
	}
	found := map[string]int{}

	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "internal/store/store.go" {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
		if err != nil {
			return err
		}
		if n := strings.Count(string(src), ".SystemPool()"); n > 0 {
			found[rel] = n
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan SystemPool production usage: %v", err)
	}

	for rel, want := range approved {
		if got := found[rel]; got != want {
			t.Errorf("SystemPool use count in %s = %d, want %d", rel, got, want)
		}
		delete(found, rel)
	}
	if len(found) == 0 {
		return
	}
	var extra []string
	for rel, n := range found {
		extra = append(extra, fmt.Sprintf("%s (%d)", rel, n))
	}
	sort.Strings(extra)
	t.Fatalf("unapproved production SystemPool use(s): %s", strings.Join(extra, ", "))
}

func TestSystemQueryMarkersExplainTenantExposure(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	var markers []string

	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, "trstctl:system-query") {
				continue
			}
			trimmed := strings.TrimSpace(line)
			where := fmt.Sprintf("%s:%d", rel, i+1)
			if !strings.HasPrefix(trimmed, "//trstctl:system-query") {
				t.Errorf("%s mentions trstctl:system-query without using the standalone marker prefix", where)
				continue
			}
			reason := strings.TrimSpace(strings.TrimPrefix(trimmed, "//trstctl:system-query"))
			if len(reason) < 40 {
				t.Errorf("%s system-query marker reason is too short: %q", where, reason)
			}
			lower := strings.ToLower(reason)
			explainsScope := strings.Contains(lower, "cross-tenant") ||
				strings.Contains(lower, "before any tenant is known") ||
				strings.Contains(lower, "tenant's rls context")
			if !explainsScope {
				t.Errorf("%s system-query marker must explain the tenant exposure boundary: %q", where, reason)
			}
			explainsWhy := strings.Contains(lower, "system") ||
				strings.Contains(lower, "by design") ||
				strings.Contains(lower, "rls") ||
				strings.Contains(lower, "tenant_id") ||
				strings.Contains(lower, "owning tenant")
			if !explainsWhy {
				t.Errorf("%s system-query marker must explain why the bypass is narrow: %q", where, reason)
			}
			markers = append(markers, where)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan system-query markers: %v", err)
	}
	if len(markers) < 10 {
		t.Fatalf("found only %d production system-query markers; guard may no longer cover the audited cross-tenant system paths", len(markers))
	}
}
