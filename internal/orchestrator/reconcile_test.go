package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// transitionEvent builds the JSON body of a lifecycle transition event the way
// Orchestrator.Transition does, so the reconciler decodes it identically.
func transitionEvent(t *testing.T, identityID string, from, to orchestrator.State) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		From       string `json:"from"`
		To         string `json:"to"`
	}{identityID, string(from), string(to)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countOutbox returns how many outbox rows exist for (tenant, idempotency_key),
// read on the pool (system role) for cross-tenant inspection in a test.
func countOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, idemKey string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantID, idemKey).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

// enqueueIfAbsent runs Outbox.EnqueueIfAbsent under the entry's tenant context,
// modelling the inline Transition enqueue.
func enqueueIfAbsent(t *testing.T, s *store.Store, ob *orchestrator.Outbox, e orchestrator.Entry) error {
	t.Helper()
	return s.WithTenant(context.Background(), e.TenantID, func(tx pgx.Tx) error {
		_, err := ob.EnqueueIfAbsent(context.Background(), tx, e)
		return err
	})
}

// TestReconcileOutboxHealsCrashGapExactlyOnce is the SPINE-011 acceptance: a crash
// between Transition's event Append and the separate transaction that projects it
// and enqueues its outbox side effect leaves the event durable but the side effect
// un-enqueued. ReconcileOutbox must re-derive the missing effect from the log and
// enqueue it EXACTLY ONCE — and a second reconcile (or a later inline retry) must
// not duplicate it.
//
// We simulate the crash by appending the lifecycle event directly to the log (the
// append committed) while NOT running the inline projection/outbox tx (the process
// "died" in the gap). The reconciler must then create the ca.issue intent. This
// must FAIL on the pre-fix tree (no reconciler exists) and PASS post-fix.
func TestReconcileOutboxHealsCrashGapExactlyOnce(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	// The orphaned event: requested -> issued carries the ca.issue side effect.
	ev, err := log.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append orphaned transition: %v", err)
	}

	// Pre-condition: no outbox effect yet (the inline tx never ran).
	if got := countOutbox(t, ctx, s.Pool(), tenantA, ev.ID); got != 0 {
		t.Fatalf("pre-reconcile outbox rows for the orphaned event = %d, want 0", got)
	}

	// Heal.
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d effects, want 1 (the lost ca.issue)", healed)
	}
	if got := countOutbox(t, ctx, s.Pool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("post-reconcile outbox rows = %d, want exactly 1 (ca.issue enqueued once)", got)
	}

	// Idempotent: a second reconcile must heal nothing and not duplicate.
	healed2, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("second ReconcileOutbox: %v", err)
	}
	if healed2 != 0 {
		t.Fatalf("second ReconcileOutbox healed %d, want 0 (already enqueued)", healed2)
	}
	if got := countOutbox(t, ctx, s.Pool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("after second reconcile outbox rows = %d, want still exactly 1 (no duplicate)", got)
	}
}

// TestReconcileOutboxSkipsEffectlessTransitions proves the reconciler only
// enqueues effects for transitions that HAVE a side effect: issued -> deployed has
// connector.deploy, but a purely internal transition (revoked -> retired) has none,
// so it is left alone.
func TestReconcileOutboxSkipsEffectlessTransitions(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	// revoked -> retired: a valid transition with NO side effect.
	if _, err := log.Append(ctx, events.Event{
		Type:     "identity.retired",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRevoked, orchestrator.StateRetired),
	}); err != nil {
		t.Fatal(err)
	}
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 0 {
		t.Fatalf("reconcile healed %d for an effectless transition, want 0", healed)
	}
}

// TestReconcileOutboxDoesNotDoubleEnqueueWithInlinePath proves the inline Transition
// path and the reconciler cooperate: when the inline path already enqueued the
// effect (the normal, no-crash case), a subsequent reconcile adds nothing. We model
// the inline enqueue with EnqueueIfAbsent keyed by the event ID (exactly what
// Transition does), then reconcile and assert no duplicate.
func TestReconcileOutboxDoesNotDoubleEnqueueWithInlinePath(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	ev, err := log.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inline path landed the effect.
	if err := enqueueIfAbsent(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "ca.issue", IdempotencyKey: ev.ID, Payload: ev.Data,
	}); err != nil {
		t.Fatalf("inline enqueue: %v", err)
	}
	// Reconcile sees the effect already present and heals nothing.
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatal(err)
	}
	if healed != 0 {
		t.Fatalf("reconcile healed %d after inline enqueue, want 0", healed)
	}
	if got := countOutbox(t, ctx, s.Pool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("outbox rows = %d, want exactly 1 (no double-enqueue)", got)
	}
}

func TestReconcileOutboxRejectsUnknownLifecycleSchemaVersion(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	ev, err := log.Append(ctx, events.Event{
		Type:          "identity.issued",
		TenantID:      tenantA,
		SchemaVersion: 99,
		Data:          transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append unknown-version transition: %v", err)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("ReconcileOutbox err = %v, want ErrUnknownSchemaVersion", err)
	}
	if healed != 0 {
		t.Fatalf("ReconcileOutbox healed %d effects before schema failure, want 0", healed)
	}
	if got := countOutbox(t, ctx, s.Pool(), tenantA, ev.ID); got != 0 {
		t.Fatalf("outbox rows after unknown schema reconcile = %d, want 0", got)
	}
}
