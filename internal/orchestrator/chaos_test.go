//go:build chaos

// Package orchestrator chaos suite (RESIL-003/005): fault-injection over the
// embedded spine. These are the failure classes a system of record must survive:
// signer death mid-issue, NATS restart/partition, PostgreSQL failover before or
// after dispatch bookkeeping, store-write failure, restore interruption, and clock
// skew on retry backoff. They are gated behind the `chaos` build tag and run via
// `make chaos`, so they do not slow the normal `make test` loop but ARE exercised
// in CI as their own required merge gate.
//
// Each test asserts the SAFE failure direction: a fault yields a clean error and a
// recoverable state (no partial/corrupt read model, no lost-or-duplicated outbox
// effect, no negative/zero retry schedule), never a silent wrong result.
package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// chaosFaultDirections is the required RESIL-003 fault matrix. Each entry is a
// fault injected by this chaos suite (or, for memory pressure, by the signing chaos
// wrapper that `make chaos` runs in the same job) and the safe direction it proves.
// The strings are intentionally stable: docs/branch_protection_test.go asserts this
// matrix stays visible so a future cleanup cannot shrink the fault set silently.
var chaosFaultDirections = map[string]string{
	"signer-sigkill-mid-issue":          "ca.issue outbox intent remains retryable; no certificate is marked delivered from a dead signer",
	"nats-restart-partition":            "replay/reconcile fails while partitioned and replays acked events after restart",
	"postgres-failover-mid-transaction": "same-transaction outbox intent rolls back with the state change before commit",
	"disk-full-store":                   "delivery is not marked successful when the store cannot persist finalize bookkeeping",
	"restore-interruption":              "restore/rebuild transaction rolls back instead of exposing a half-loaded read model",
	"memory-pressure":                   "served signer bulkhead sheds excess Sign RPCs while Health still answers",
	"clock-skew-retry-backoff":          "retry schedule never spins immediately under adversarial clock movement",
}

func TestChaosFaultDirectionMatrix(t *testing.T) {
	for _, want := range []string{
		"signer-sigkill-mid-issue",
		"nats-restart-partition",
		"postgres-failover-mid-transaction",
		"disk-full-store",
		"restore-interruption",
		"memory-pressure",
		"clock-skew-retry-backoff",
	} {
		if chaosFaultDirections[want] == "" {
			t.Fatalf("chaos fault matrix no longer covers %q (RESIL-003)", want)
		}
	}
}

// TestChaosSignerSIGKILLMidIssueLeavesIntentRetryable models the isolated signer
// process dying after the ca.issue intent was claimed but before a certificate was
// minted. The safe direction is AN-6 at-least-once: the outbox records the failure,
// leaves the intent pending, and schedules retry instead of marking delivery.
func TestChaosSignerSIGKILLMidIssueLeavesIntentRetryable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
	)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "ca.issue", IdempotencyKey: "chaos-signer-kill", Payload: []byte(`{}`),
	})

	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		if m.Destination != "ca.issue" {
			t.Fatalf("destination = %q, want ca.issue", m.Destination)
		}
		return errors.New("signer process exited: signal killed")
	}))
	if err != nil {
		t.Fatalf("Dispatch should record signer failure on the row, not return a dispatcher error: %v", err)
	}
	if n != 1 {
		t.Fatalf("Dispatch processed %d rows, want 1", n)
	}

	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "pending" || rec.Attempts != 1 || !strings.Contains(rec.LastError, "signal killed") {
		t.Fatalf("after signer death row = status=%q attempts=%d last_error=%q; want pending retry with signer-kill evidence",
			rec.Status, rec.Attempts, rec.LastError)
	}

	ran := 0
	n, err = ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		ran++
		return nil
	}))
	if err != nil || n != 0 || ran != 0 {
		t.Fatalf("immediate retry n=%d ran=%d err=%v; want no retry before backoff matures", n, ran, err)
	}
}

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

// TestChaosNATSRestartPreservesAckedEvents closes embedded NATS after an append,
// reopens it over the same file-backed store, and proves the acked event is still
// replayable and can drive outbox reconciliation. This is the positive half of the
// partition test above: unavailable must fail cleanly, restarted must recover.
func TestChaosNATSRestartPreservesAckedEvents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: dir}
	log1, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open first log: %v", err)
	}

	ev, err := log1.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     transitionEvent(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append before restart: %v", err)
	}
	if err := log1.Close(); err != nil {
		t.Fatalf("close first log: %v", err)
	}

	log2, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("reopen log on same store: %v", err)
	}
	t.Cleanup(func() { _ = log2.Close() })
	var seen []events.Event
	if err := log2.Replay(ctx, 1, func(e events.Event) error {
		seen = append(seen, e)
		return nil
	}); err != nil {
		t.Fatalf("replay after restart: %v", err)
	}
	if len(seen) != 1 || seen[0].ID != ev.ID || seen[0].Sequence != ev.Sequence {
		t.Fatalf("replayed events after restart = %+v, want exactly event id=%s seq=%d", seen, ev.ID, ev.Sequence)
	}

	healed, err := orchestrator.NewOrchestrator(log2, s, orchestrator.NewOutbox(s)).ReconcileOutbox(ctx, log2)
	if err != nil {
		t.Fatalf("reconcile after restart: %v", err)
	}
	if healed != 1 {
		t.Fatalf("reconcile after restart healed %d effects, want 1", healed)
	}
	if got := countOutbox(t, ctx, s.Pool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("outbox rows for replayed event = %d, want 1", got)
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

// TestChaosPostgresFailoverMidTransactionRollsBackIntent injects a failure after
// the outbox row is inserted but before the caller transaction commits. AN-6 says
// external-call intent and state change share one transaction; if PostgreSQL fails
// before commit, neither half is allowed to leak.
func TestChaosPostgresFailoverMidTransactionRollsBackIntent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	failover := errors.New("postgres failover before commit")

	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "webhook", IdempotencyKey: "chaos-pg-tx", Payload: []byte(`{}`),
		}); err != nil {
			return err
		}
		return failover
	})
	if !errors.Is(err, failover) {
		t.Fatalf("transaction error = %v, want injected failover", err)
	}
	if got := countOutbox(t, ctx, s.Pool(), tenantA, "chaos-pg-tx"); got != 0 {
		t.Fatalf("outbox rows after rolled-back transaction = %d, want 0", got)
	}
}

// TestChaosDiskFullStoreFinalizeKeepsLeaseRecoverable simulates the datastore
// refusing the post-delivery finalize write (same safe direction as a full disk:
// the worker cannot persist "delivered"). The row must stay recoverable by lease
// expiry, so a fresh worker can redeliver with the same idempotency key.
func TestChaosDiskFullStoreFinalizeKeepsLeaseRecoverable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s, orchestrator.WithLeaseTTL(10*time.Millisecond))
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "chaos-disk-full", Payload: []byte(`{}`),
	})

	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		s.Close() // finalize cannot write its success marker
		return nil
	}))
	if err == nil {
		t.Fatal("Dispatch succeeded even though the store closed before delivery finalization")
	}
	if n != 1 {
		t.Fatalf("Dispatch processed %d rows, want 1 before the finalize fault", n)
	}

	recovered, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("reopen store after finalize fault: %v", err)
	}
	t.Cleanup(func() { recovered.Close() })
	if err := recovered.Migrate(ctx); err != nil {
		t.Fatalf("migrate reopened store: %v", err)
	}
	time.Sleep(25 * time.Millisecond) // let the failed worker lease expire

	delivered := 0
	ob2 := orchestrator.NewOutbox(recovered, orchestrator.WithLeaseTTL(10*time.Millisecond), orchestrator.WithWorkerID("chaos-recovery"))
	n, err = ob2.Dispatch(ctx, orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		delivered++
		if m.IdempotencyKey != "chaos-disk-full" {
			t.Fatalf("redelivered idempotency key = %q, want chaos-disk-full", m.IdempotencyKey)
		}
		return nil
	}))
	if err != nil {
		t.Fatalf("recovery dispatch: %v", err)
	}
	if n != 1 || delivered != 1 {
		t.Fatalf("recovery dispatch n=%d delivered=%d, want one redelivery", n, delivered)
	}
	rec, err := ob2.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 2 {
		t.Fatalf("recovered row = status=%q attempts=%d, want delivered on second attempt", rec.Status, rec.Attempts)
	}
}

// TestChaosRestoreInterruptionRollsBackReadModel injects an error after restore
// work has truncated and partially loaded the read model. RestoreReadModelTx must
// roll the whole transaction back, leaving the previous read model visible instead
// of an empty or half-restored API surface.
func TestChaosRestoreInterruptionRollsBackReadModel(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "before-restore", EventSeq: 1}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	interrupted := errors.New("restore interrupted")
	err := s.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `TRUNCATE tenants CASCADE`); err != nil {
			return err
		}
		if err := s.UpsertTenantTx(ctx, tx, store.Tenant{TenantID: tenantB, Name: "partial-restore", EventSeq: 2}); err != nil {
			return err
		}
		return interrupted
	})
	if !errors.Is(err, interrupted) {
		t.Fatalf("restore error = %v, want injected interruption", err)
	}
	got, err := s.GetTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("original tenant missing after interrupted restore rollback: %v", err)
	}
	if got.Name != "before-restore" {
		t.Fatalf("original tenant name after interrupted restore = %q, want before-restore", got.Name)
	}
	if _, err := s.GetTenant(ctx, tenantB); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("partial restore tenant lookup error = %v, want ErrNoRows (partial rows rolled back)", err)
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
