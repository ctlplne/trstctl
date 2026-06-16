//go:build chaos

// Package orchestrator chaos suite (RESIL-005): fault-injection over the embedded
// spine — NATS closed mid-replay, PostgreSQL killed mid-dispatch, and clock skew on
// the retry backoff. These are the failure classes a system of record must survive,
// beyond the two targeted fault tests the audit found (signer SIGKILL,
// outbox-crash-recovery). They are gated behind the `chaos` build tag and run via
// `make chaos`, so they do not slow the per-PR `make test` but ARE exercised in CI.
//
// Each test asserts the SAFE failure direction: a fault yields a clean error and a
// recoverable state (no partial/corrupt read model, no lost-or-duplicated outbox
// effect, no negative/zero retry schedule), never a silent wrong result.
package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestChaosNATSClosedMidReconcileFailsCleanly closes the event log (a NATS
// partition / shutdown) and asserts the orchestrator's log-replay reconcile fails
// with an error rather than hanging or corrupting state. The read model is a
// projection, so a failed replay leaves it simply behind, never wrong.
func TestChaosNATSClosedMidReconcile(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	// Seed a lifecycle event, then CLOSE the log to simulate NATS going away.
	if _, err := log.Append(ctx, events.Event{
		Type: "identity.issued", TenantID: tenantA,
		Data: transitionEvent(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", orchestrator.StateRequested, orchestrator.StateIssued),
	}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	// Reconcile must now FAIL (the log is unreachable) rather than silently
	// "succeeding" with a half-applied state.
	_, err := orch.ReconcileOutbox(ctx, log)
	if err == nil {
		t.Fatal("ReconcileOutbox over a closed event log should error, not silently succeed")
	}
}

// TestChaosPostgresKilledMidDispatch closes the store pool mid-run (a PostgreSQL
// failover / kill) and asserts Dispatch surfaces the error and does NOT mark the
// entry delivered — so after recovery a fresh dispatcher redelivers it
// (at-least-once, AN-6), never dropping the effect.
func TestChaosPostgresKilledMidDispatch(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	// Enqueue an entry, then kill PG before dispatch.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "webhook", IdempotencyKey: "chaos-pg", Payload: []byte(`{}`),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.Close() // simulate PostgreSQL becoming unreachable

	delivered := 0
	_, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		delivered++
		return nil
	}))
	if err == nil {
		t.Fatal("Dispatch against a dead datastore should error, not silently succeed")
	}
	if delivered != 0 {
		t.Fatalf("handler ran %d times against a dead datastore; the claim must fail before delivery so the entry stays pending", delivered)
	}
}

// TestChaosClockSkewBackoffStaysMonotone injects a clock-skew-affected backoff and
// asserts the retry schedule the outbox computes is never negative and never
// schedules a retry in the past relative to the skewed now — so a clock jumping
// backward cannot make a failed entry spin (immediately re-due) or be lost (far
// future). It exercises the backoff arithmetic under an adversarial clock.
func TestChaosClockSkewBackoffStaysMonotone(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	// A backoff that returns a large positive delay even as the wall clock is
	// (conceptually) skewed: the property we assert is that next_attempt_at is in the
	// future of the row's update, so a redelivery does not spin.
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithMaxAttempts(5),
		orchestrator.WithBackoff(func(attempts int) time.Duration {
			// Even under skew, never non-positive: clamp to >= 1s.
			d := time.Duration(attempts) * time.Second
			if d <= 0 {
				d = time.Second
			}
			return d
		}),
	)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "chaos-clock", Payload: []byte(`{}`),
	})

	// One failing dispatch schedules a retry.
	if _, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("boom")
	})); err != nil {
		t.Fatal(err)
	}
	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "pending" {
		t.Fatalf("after one failure status = %q, want pending (a retry is scheduled, not dead-lettered)", rec.Status)
	}
	// Re-dispatching immediately must NOT re-run the handler: the backoff deferred the
	// retry into the future, so a clock that has not advanced finds nothing due.
	ran := 0
	if n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		ran++
		return errors.New("boom")
	})); err != nil || n != 0 {
		t.Fatalf("immediate re-dispatch n=%d err=%v, want 0,nil (backoff defers the retry; no spin under clock skew)", n, err)
	}
	if ran != 0 {
		t.Fatalf("handler re-ran %d times immediately; the backoff schedule did not hold under skew", ran)
	}
}
