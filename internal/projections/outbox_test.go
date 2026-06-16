package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// forcePending resets an outbox row to pending, simulating a redelivery (a crash
// after the handler ran but before the "delivered" mark stuck). It is a raw test
// fixture, run as the system role.
func forcePending(t *testing.T, s *store.Store, id int64) {
	t.Helper()
	if _, err := s.Pool().Exec(context.Background(),
		"UPDATE outbox SET status='pending', delivered_at=NULL, next_attempt_at=now() WHERE id=$1", id); err != nil {
		t.Fatalf("force pending: %v", err)
	}
}

func enqueue(t *testing.T, s *store.Store, ob *orchestrator.Outbox, e orchestrator.Entry) int64 {
	t.Helper()
	var id int64
	if err := s.WithTenant(context.Background(), e.TenantID, func(tx pgx.Tx) error {
		var err error
		id, err = ob.Enqueue(context.Background(), tx, e)
		return err
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return id
}

// TestOutboxCrashRecoversAndDelivers is the AN-6 crash-recovery acceptance: the
// intent is written in the same transaction as the state change, so after a
// crash between the state write and dispatch a fresh dispatcher still delivers.
func TestOutboxCrashRecoversAndDelivers(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	// A state change and the outbox enqueue commit in ONE transaction.
	var enqueuedID int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			"INSERT INTO idempotency_keys (tenant_id, key, status) VALUES ($1, $2, 'completed')",
			tenantA, "outbox-state"); err != nil {
			return err
		}
		id, err := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       tenantA,
			Destination:    "webhook",
			IdempotencyKey: "deliver-1",
			Payload:        []byte(`{"event":"tenant.registered"}`),
		})
		enqueuedID = id
		return err
	}); err != nil {
		t.Fatalf("commit state+outbox: %v", err)
	}
	if enqueuedID == 0 {
		t.Fatal("Enqueue returned no id")
	}

	// --- simulate a crash: the process dies after commit, before dispatch ---

	// Recovery: a brand-new dispatcher over the same database finds the durable
	// entry and delivers it.
	var delivered []orchestrator.Message
	recovered := orchestrator.NewOutbox(s)
	n, err := recovered.Dispatch(ctx, orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		delivered = append(delivered, m)
		return nil
	}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 1 || len(delivered) != 1 {
		t.Fatalf("dispatched %d (delivered %d), want exactly 1 after recovery", n, len(delivered))
	}
	if delivered[0].IdempotencyKey != "deliver-1" || delivered[0].Destination != "webhook" {
		t.Errorf("delivered %+v, want the enqueued webhook/deliver-1 message", delivered[0])
	}

	// The state change committed in the same transaction survived too.
	var stateRows int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1 AND key = $2",
			tenantA, "outbox-state").Scan(&stateRows)
	}); err != nil {
		t.Fatal(err)
	}
	if stateRows != 1 {
		t.Errorf("state row count = %d, want 1 (it must commit alongside the outbox entry)", stateRows)
	}

	// Nothing remains pending after delivery.
	pending, err := recovered.Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("%d entries still pending, want 0", len(pending))
	}
}

// TestOutboxRollbackPersistsNothing proves the enqueue is bound to the caller's
// transaction: if the state change rolls back, the outbox entry does too (AN-6).
func TestOutboxRollbackPersistsNothing(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	boom := errors.New("boom")
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			"INSERT INTO idempotency_keys (tenant_id, key, status) VALUES ($1, $2, 'completed')",
			tenantA, "rolled-back"); e != nil {
			return e
		}
		if _, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "webhook", IdempotencyKey: "never", Payload: []byte("x"),
		}); e != nil {
			return e
		}
		return boom // abort: both the state row and the outbox entry roll back
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTenant err = %v, want boom", err)
	}

	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		t.Fatal("handler must not run; the enqueue rolled back with the state")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("dispatched %d, want 0 (the enqueue rolled back)", n)
	}
}

// TestOutboxDuplicateDispatchOneEffect is the AN-6 idempotent-effect acceptance:
// at-least-once delivery, but a receiver that dedupes on the carried key sees one
// effect. It also shows a delivered row is not re-claimed by a normal dispatch.
func TestOutboxDuplicateDispatchOneEffect(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "ca", IdempotencyKey: "issue-42", Payload: []byte("csr"),
	})

	deliveries := 0
	effects := map[string]int{} // a real receiver dedupes on the key; we record raw
	handler := orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		deliveries++
		effects[m.IdempotencyKey]++
		return nil
	})

	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("first dispatch = %d, %v; want 1", n, err)
	}
	// A normal second dispatch is a no-op: the row is already delivered.
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 0 {
		t.Fatalf("second dispatch = %d, %v; want 0 (delivered rows are not re-claimed)", n, err)
	}
	// Force a redelivery (crash after Deliver, before the mark stuck).
	forcePending(t, s, id)
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("redelivery dispatch = %d, %v; want 1", n, err)
	}

	if deliveries < 2 {
		t.Errorf("handler ran %d time(s); at-least-once redelivery should call it again", deliveries)
	}
	if len(effects) != 1 {
		t.Errorf("distinct effects = %v, want exactly one (idempotent on the carried key)", effects)
	}
}

// TestOutboxRetryStateObservable is the AN-6 observable-retries acceptance: a
// failed delivery records the attempt and error and stays pending, then a later
// dispatch retries and succeeds.
func TestOutboxRetryStateObservable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }), // retry immediately
		orchestrator.WithMaxAttempts(3))

	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "flaky", IdempotencyKey: "retry-1", Payload: []byte("p"),
	})

	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("connector unavailable")
	})
	if n, err := ob.Dispatch(ctx, failing); err != nil || n != 1 {
		t.Fatalf("dispatch(failing) = %d, %v; want 1 processed (a handler failure is not a dispatch error)", n, err)
	}

	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 after one failure", rec.Attempts)
	}
	if rec.Status != "pending" {
		t.Errorf("status = %q, want pending (attempts remain)", rec.Status)
	}
	if rec.LastError == "" {
		t.Errorf("last_error empty; the failure must be observable")
	}

	// The entry is still due, so a later dispatch retries it — and succeeds.
	ok := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return nil })
	if n, err := ob.Dispatch(ctx, ok); err != nil || n != 1 {
		t.Fatalf("retry dispatch = %d, %v; want 1", n, err)
	}
	rec, err = ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" {
		t.Errorf("status = %q, want delivered after a successful retry", rec.Status)
	}
}

// TestOutboxDeadLettersAfterMaxAttempts shows the terminal retry state: once
// attempts reach the cap, the entry is marked failed and no longer dispatched.
func TestOutboxDeadLettersAfterMaxAttempts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithMaxAttempts(2))

	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "dead", IdempotencyKey: "dl-1", Payload: []byte("p"),
	})

	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("always down")
	})
	if _, err := ob.Dispatch(ctx, failing); err != nil { // attempt 1 -> pending
		t.Fatal(err)
	}
	if _, err := ob.Dispatch(ctx, failing); err != nil { // attempt 2 -> failed (cap)
		t.Fatal(err)
	}

	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "failed" || rec.Attempts != 2 {
		t.Errorf("rec = {status:%q attempts:%d}, want failed/2", rec.Status, rec.Attempts)
	}

	// A dead-lettered entry is no longer claimed.
	if n, err := ob.Dispatch(ctx, failing); err != nil || n != 0 {
		t.Errorf("dispatch after dead-letter = %d, %v; want 0", n, err)
	}
}
