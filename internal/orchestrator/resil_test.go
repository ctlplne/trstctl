package orchestrator_test

import (
	"context"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestConcurrentProjectorsConvergeUnderAdvisoryLock is the RESIL-004 acceptance:
// when more than one projector catches up against the SAME store concurrently (the
// multi-replica boot the isolated-signer HA preset unlocks), they must converge to
// exactly the single-projector read-model state — no double-applied rows, no
// corruption. The projection advisory lock (RESIL-004) serializes the catch-ups so
// they cannot interleave into the shared read-model tables.
//
// On the pre-fix tree (no advisory lock, per-replica catch-up replaying from
// sequence 0) two projectors race into the same tables; this test exercises the
// post-fix serialized path and asserts convergence. It runs the real embedded
// PostgreSQL + in-process NATS, never mocks.
func TestConcurrentProjectorsConvergeUnderAdvisoryLock(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()

	// Seed a representative read model: a tenant, several owners, and a couple of
	// lifecycle-relevant entities, appended out of band so the read model is behind.
	mustAppendEv(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("Acme")})
	owners := []struct{ id, name string }{
		{"00000000-0000-0000-0000-0000000000e1", "one"},
		{"00000000-0000-0000-0000-0000000000e2", "two"},
		{"00000000-0000-0000-0000-0000000000e3", "three"},
		{"00000000-0000-0000-0000-0000000000e4", "four"},
		{"00000000-0000-0000-0000-0000000000e5", "five"},
	}
	for _, o := range owners {
		mustAppendEv(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreatedJSON(o.id, o.name)})
	}

	// Run N projectors catching up at the same time. The advisory lock serializes
	// them; each is its own *Projector over the same store (separate logical
	// replicas would each construct one).
	const replicas = 4
	var wg sync.WaitGroup
	errs := make([]error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := projections.New(s)
			errs[idx] = p.ProjectCatchUp(ctx, log)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("projector %d catch-up failed: %v", i, err)
		}
	}

	// Convergence: exactly the seeded owners, each exactly once (no duplicates from a
	// racing double-apply). The projector upserts by id, and the serialized catch-up
	// keeps the apply ordering single-threaded.
	got := ownerNames(t, s, tenantA)
	if len(got) != len(owners) {
		t.Fatalf("converged owner count = %d, want %d (no duplicates, no drops)", len(got), len(owners))
	}
	for _, o := range owners {
		if got[o.id] != o.name {
			t.Errorf("owner %s = %q, want %q", o.id, got[o.id], o.name)
		}
	}

	// The checkpoint converged to the log head exactly once.
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp != head {
		t.Fatalf("converged checkpoint = %d, want head %d", cp, head)
	}
}

func mustAppendEv(t *testing.T, log *events.Log, e events.Event) {
	t.Helper()
	if _, err := log.Append(context.Background(), e); err != nil {
		t.Fatalf("append %s: %v", e.Type, err)
	}
}

func ownerNames(t *testing.T, s *store.Store, tenantID string) map[string]string {
	t.Helper()
	rows, err := s.Pool().Query(context.Background(),
		`SELECT id::text, name FROM owners WHERE tenant_id = $1`, tenantID)
	if err != nil {
		t.Fatalf("query owners: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatal(err)
		}
		out[id] = name
	}
	return out
}
