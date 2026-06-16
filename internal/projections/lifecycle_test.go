package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// seedIdentity creates an owner and a freshly-requested identity so the
// orchestrator has something to drive through its lifecycle.
func seedIdentity(t *testing.T, s *store.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertOwner(ctx, store.Owner{ID: idOwner, TenantID: tenantID, Kind: store.OwnerService, Name: "svc"}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := s.UpsertIdentity(ctx, store.Identity{
		ID: idIdentity, TenantID: tenantID, Kind: store.KindX509Certificate,
		Name: "svc.acme.test", OwnerID: idOwner, Status: string(orchestrator.StateRequested),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

// identityEvents replays the log and returns the lifecycle event types for the
// identity, in order.
func identityEvents(t *testing.T, log *events.Log, tenantID, identityID string) []string {
	t.Helper()
	var types []string
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.TenantID == tenantID && len(e.Type) > len("identity.") && e.Type[:len("identity.")] == "identity." {
			types = append(types, e.Type)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	return types
}

// TestLifecycleValidTransitionsEmitEvents is the acceptance: each valid
// transition emits the right event, and the read model tracks the state.
func TestLifecycleValidTransitionsEmitEvents(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	for _, to := range []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRenewing, orchestrator.StateDeployed,
	} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, ""); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	got := identityEvents(t, log, tenantA, idIdentity)
	want := []string{"identity.issued", "identity.deployed", "identity.renewing", "identity.renewed"}
	if len(got) != len(want) {
		t.Fatalf("emitted events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, got[i], want[i])
		}
	}

	// The read model and the log-reconstructed state agree on the final state.
	st, err := orch.State(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if st != orchestrator.StateDeployed {
		t.Errorf("reconstructed state = %s, want deployed", st)
	}
	ident, err := s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != string(orchestrator.StateDeployed) {
		t.Errorf("read-model status = %s, want deployed", ident.Status)
	}
}

// TestLifecycleInvalidTransitionRejected is the acceptance: an illegal transition
// is rejected with a structured error and has no effect.
func TestLifecycleInvalidTransitionRejected(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	// requested -> deployed skips issuance and must be rejected.
	err := orch.Transition(ctx, tenantA, idIdentity, orchestrator.StateDeployed, "")
	if !errors.Is(err, orchestrator.ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}
	var te *orchestrator.TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *TransitionError", err)
	}
	if te.From != orchestrator.StateRequested || te.To != orchestrator.StateDeployed || te.IdentityID != idIdentity {
		t.Errorf("transition error = %+v, want requested->deployed for %s", te, idIdentity)
	}

	// No event was emitted and the status is unchanged.
	if got := identityEvents(t, log, tenantA, idIdentity); len(got) != 0 {
		t.Errorf("a rejected transition emitted events: %v", got)
	}
	ident, err := s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != string(orchestrator.StateRequested) {
		t.Errorf("status = %s after a rejected transition, want requested", ident.Status)
	}

	// A terminal state rejects all further transitions.
	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateRevoked, orchestrator.StateRetired} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, ""); err != nil {
			t.Fatalf("driving to retired (%s): %v", to, err)
		}
	}
	if err := orch.Transition(ctx, tenantA, idIdentity, orchestrator.StateIssued, ""); !errors.Is(err, orchestrator.ErrInvalidTransition) {
		t.Errorf("transition out of retired = %v, want ErrInvalidTransition", err)
	}
}

// TestLifecycleReconstructableFromLog is the acceptance: an identity's transition
// history and current state can be rebuilt purely from the event log.
func TestLifecycleReconstructableFromLog(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	steps := []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked, orchestrator.StateRetired,
	}
	for _, to := range steps {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, "test"); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	// A fresh orchestrator over the same log reconstructs the same history/state,
	// proving the lifecycle is derived from the log and not in-memory.
	fresh := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	hist, err := fresh.History(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	wantFrom := []orchestrator.State{orchestrator.StateRequested, orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked}
	wantTo := steps
	if len(hist) != len(wantTo) {
		t.Fatalf("history has %d transitions, want %d (%v)", len(hist), len(wantTo), hist)
	}
	for i := range hist {
		if hist[i].From != wantFrom[i] || hist[i].To != wantTo[i] {
			t.Errorf("transition %d = %s->%s, want %s->%s", i, hist[i].From, hist[i].To, wantFrom[i], wantTo[i])
		}
		if i > 0 && hist[i].Sequence <= hist[i-1].Sequence {
			t.Errorf("transition %d sequence %d not increasing", i, hist[i].Sequence)
		}
	}
	st, err := fresh.State(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if st != orchestrator.StateRetired {
		t.Errorf("reconstructed state = %s, want retired", st)
	}
}

// TestLifecycleOutboxSideEffects is the acceptance for outbox-driven side
// effects: transitions that require an external call enqueue an outbox entry in
// the same transaction as the state change, keyed by the emitting event.
func TestLifecycleOutboxSideEffects(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, ""); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	pending, err := ob.Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	gotDest := map[string]bool{}
	for _, r := range pending {
		gotDest[r.Destination] = true
		if r.IdempotencyKey == "" {
			t.Errorf("outbox entry %d has no idempotency key (should be the emitting event id)", r.ID)
		}
	}
	for _, want := range []string{"ca.issue", "connector.deploy", "revocation.publish"} {
		if !gotDest[want] {
			t.Errorf("missing outbox side effect %q; got destinations %v", want, gotDest)
		}
	}
}

// seedIdentityID creates an owner (reusing one per tenant) and a fresh requested
// identity with the given id, so a test can build a multi-identity, multi-tenant
// estate for the bounded-history assertion.
func seedIdentityID(t *testing.T, s *store.Store, tenantID, ownerID, identityID string) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertOwner(ctx, store.Owner{ID: ownerID, TenantID: tenantID, Kind: store.OwnerService, Name: "svc"}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := s.UpsertIdentity(ctx, store.Identity{
		ID: identityID, TenantID: tenantID, Kind: store.KindX509Certificate,
		Name: "svc.acme.test", OwnerID: ownerID, Status: string(orchestrator.StateRequested),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

// TestHistoryIsTenantScopedAndBounded is the SPINE-001 acceptance. Pre-fix,
// History/State called log.Replay(ctx, 0, …) and scanned EVERY event across ALL
// tenants on every call (O(total events)). Now they read the per-identity
// identity_transitions projection: the work is bounded by this identity's own
// transitions and confined to its tenant by RLS. The test drives one transition
// for tenant A, floods tenant B with unrelated transitions, then proves via
// EXPLAIN ANALYZE that reading A's history touches only A's row(s) and removes ~0
// rows by filter — i.e. it is O(this identity), not O(total log).
func TestHistoryIsTenantScopedAndBounded(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	const (
		ownerA = "a0000000-0000-0000-0000-0000000000a1"
		identA = "a0000000-0000-0000-0000-0000000000a3"
		ownerB = "b0000000-0000-0000-0000-0000000000b1"
	)
	seedIdentityID(t, s, tenantA, ownerA, identA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	// Tenant A: a single transition.
	if err := orch.Transition(ctx, tenantA, identA, orchestrator.StateIssued, "first"); err != nil {
		t.Fatalf("A transition: %v", err)
	}

	// Tenant B: a large, unrelated cross-tenant volume — exactly what the pre-fix
	// replay walked on every call.
	bSteps := []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRenewing, orchestrator.StateDeployed,
		orchestrator.StateRenewing, orchestrator.StateDeployed,
	}
	const bIdentities = 40
	for i := 0; i < bIdentities; i++ {
		bid := fmt.Sprintf("b0000000-0000-0000-0000-%012d", i+1)
		seedIdentityID(t, s, tenantB, ownerB, bid)
		for _, to := range bSteps {
			if err := orch.Transition(ctx, tenantB, bid, to, "noise"); err != nil {
				t.Fatalf("B transition: %v", err)
			}
		}
	}

	// History/State for A return exactly A's data, independent of B's volume.
	hist, err := orch.History(ctx, tenantA, identA)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 || hist[0].From != orchestrator.StateRequested || hist[0].To != orchestrator.StateIssued {
		t.Fatalf("A history = %+v, want exactly requested->issued", hist)
	}
	if st, err := orch.State(ctx, tenantA, identA); err != nil || st != orchestrator.StateIssued {
		t.Fatalf("A state = %s (err %v), want issued", st, err)
	}

	// EXPLAIN ANALYZE the exact query History runs: the access path must return only
	// A's rows. A full scan (the pre-fix shape) would remove ~all of B's rows by
	// filter; the indexed per-identity read removes ~0.
	totalTransitions := 1 + bIdentities*len(bSteps)
	var rowsRemoved, actualRows float64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`EXPLAIN (ANALYZE, FORMAT JSON)
			 SELECT seq, from_state, to_state, event_type, reason, occurred_at
			   FROM identity_transitions
			  WHERE tenant_id = $1 AND identity_id = $2
			  ORDER BY seq`, tenantA, identA)
		if err != nil {
			return err
		}
		defer rows.Close()
		var plan []map[string]any
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &plan); err != nil {
				return err
			}
		}
		if len(plan) == 0 {
			return fmt.Errorf("no plan returned")
		}
		node, _ := plan[0]["Plan"].(map[string]any)
		rowsRemoved = planMaxRowsRemoved(node)
		actualRows = planFloat(node["Actual Rows"])
		return rows.Err()
	}); err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	t.Logf("table has %d transitions; reading A's history examined actual_rows=%v, removed_by_filter=%v",
		totalTransitions, actualRows, rowsRemoved)

	if rowsRemoved > float64(len(bSteps)) {
		t.Fatalf("History scanned cross-tenant/foreign rows: removed %v by filter (table has %d); "+
			"a bounded per-identity read removes ~0, not O(total)", rowsRemoved, totalTransitions)
	}
	if actualRows > float64(1+len(bSteps)) {
		t.Fatalf("History examined %v rows for a 1-transition identity (table has %d); expected O(this identity)",
			actualRows, totalTransitions)
	}
}

// TestHistoryReconstructableFromTransitionProjection is the SPINE-001 AN-2
// guard: the transition read model is a pure projection of the event log. Wiping
// it and replaying the log via the production projector reproduces the identical
// history — so the log stays the source of truth even though History no longer
// reads it directly.
func TestHistoryReconstructableFromTransitionProjection(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked, orchestrator.StateRetired} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, "x"); err != nil {
			t.Fatalf("transition %s: %v", to, err)
		}
	}
	before, err := orch.History(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 4 {
		t.Fatalf("history has %d transitions, want 4", len(before))
	}

	// Rebuild the entire read model from the log (truncate + replay) via the real
	// projector, then re-read: the history must be byte-identical (AN-2).
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	after, err := orch.History(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("history after rebuild = %d, want %d", len(after), len(before))
	}
	for i := range before {
		if before[i].From != after[i].From || before[i].To != after[i].To ||
			before[i].Sequence != after[i].Sequence || before[i].Event != after[i].Event {
			t.Fatalf("transition %d changed after rebuild: %+v vs %+v", i, before[i], after[i])
		}
	}
}

// planMaxRowsRemoved returns the largest "Rows Removed by Filter" anywhere in the
// plan tree (a sequential scan of the whole table would report ~the table size).
func planMaxRowsRemoved(node map[string]any) float64 {
	if node == nil {
		return 0
	}
	max := planFloat(node["Rows Removed by Filter"])
	if subs, ok := node["Plans"].([]any); ok {
		for _, sub := range subs {
			if sm, ok := sub.(map[string]any); ok {
				if v := planMaxRowsRemoved(sm); v > max {
					max = v
				}
			}
		}
	}
	return max
}

func planFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
