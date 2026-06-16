package orchestrator_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// enqueue records an outbox entry under its tenant context and returns its id.
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

// TestOutboxDeadLettersAtMaxAttempts is the dead-letter boundary (SPINE-012): an
// entry whose handler keeps failing is retried until the attempt cap, then marked
// failed and never dispatched again. With maxAttempts=3 and a zero backoff, three
// Dispatch sweeps must take it: pending -> pending -> failed.
func TestOutboxDeadLettersAtMaxAttempts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithMaxAttempts(3),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "dead-1", Payload: []byte(`{}`),
	})

	attempts := 0
	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		attempts++
		return errors.New("boom")
	})

	// Each Dispatch drains the currently-due backlog; with a zero backoff the entry
	// is immediately due again, so ONE Dispatch call would spin — but Dispatch breaks
	// when it re-sees an already-handled id. So we sweep three times.
	for i := 0; i < 3; i++ {
		if _, err := ob.Dispatch(ctx, failing); err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
	}
	if attempts != 3 {
		t.Fatalf("handler attempts = %d, want 3 (one per sweep up to the cap)", attempts)
	}

	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "failed" {
		t.Fatalf("status = %q after %d attempts, want \"failed\" (dead-lettered at the cap)", rec.Status, rec.Attempts)
	}
	if rec.Attempts != 3 {
		t.Fatalf("recorded attempts = %d, want 3", rec.Attempts)
	}

	// A dead-lettered entry is not dispatched again: a further sweep is a no-op.
	before := attempts
	if _, err := ob.Dispatch(ctx, failing); err != nil {
		t.Fatal(err)
	}
	if attempts != before {
		t.Fatalf("a failed entry was re-dispatched (attempts %d -> %d); dead-letter must be terminal", before, attempts)
	}
}

// TestOutboxBackoffDefersRetry is the backoff arithmetic (SPINE-012): a failed
// entry is scheduled into the future (next_attempt_at = now + backoff(attempts)), so
// it is NOT due on an immediate re-sweep. With a long backoff, the second sweep must
// skip it.
func TestOutboxBackoffDefersRetry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
	)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "backoff-1", Payload: []byte(`{}`),
	})

	attempts := 0
	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		attempts++
		return errors.New("boom")
	})
	if n, err := ob.Dispatch(ctx, failing); err != nil || n != 1 {
		t.Fatalf("first dispatch n=%d err=%v, want 1, nil", n, err)
	}
	// The retry is an hour out, so a second sweep finds nothing due.
	if n, err := ob.Dispatch(ctx, failing); err != nil || n != 0 {
		t.Fatalf("second dispatch n=%d err=%v, want 0, nil (entry deferred by backoff)", n, err)
	}
	if attempts != 1 {
		t.Fatalf("handler attempts = %d, want 1 (backoff must defer the retry)", attempts)
	}
}

// TestOutboxDeliversAndMarksDelivered is the happy path: a succeeding handler marks
// the entry delivered, and it is not dispatched again.
func TestOutboxDeliversAndMarksDelivered(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "ok-1", Payload: []byte(`{"x":1}`),
	})

	var got []orchestrator.Message
	h := orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		got = append(got, m)
		return nil
	})
	if n, err := ob.Dispatch(ctx, h); err != nil || n != 1 {
		t.Fatalf("dispatch n=%d err=%v, want 1, nil", n, err)
	}
	if len(got) != 1 || got[0].IdempotencyKey != "ok-1" || got[0].TenantID != tenantA {
		t.Fatalf("delivered message = %+v, want the ok-1 entry carrying its tenant", got)
	}
	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" {
		t.Fatalf("status = %q, want delivered", rec.Status)
	}
	// A second sweep delivers nothing more.
	if n, err := ob.Dispatch(ctx, h); err != nil || n != 0 {
		t.Fatalf("re-dispatch n=%d err=%v, want 0, nil", n, err)
	}
}

// TestDispatchOneSkipLockedDoesNotDoubleDeliver is the FOR UPDATE SKIP LOCKED claim
// guarantee (SPINE-012): two dispatchers sweeping the same single due entry
// concurrently must deliver it exactly once between them, never twice. One claims
// the row; the other skips the locked row and finds nothing.
func TestDispatchOneSkipLockedDoesNotDoubleDeliver(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "race-1", Payload: []byte(`{}`),
	})

	var mu sync.Mutex
	delivered := 0
	// The handler blocks briefly so both dispatchers overlap on the claim window.
	h := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		delivered++
		mu.Unlock()
		return nil
	})

	var wg sync.WaitGroup
	totals := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n, err := ob.Dispatch(ctx, h)
			if err != nil {
				t.Errorf("dispatch %d: %v", idx, err)
			}
			totals[idx] = n
		}(i)
	}
	wg.Wait()

	if delivered != 1 {
		t.Fatalf("entry delivered %d times under concurrent dispatch, want exactly 1 (SKIP LOCKED claim)", delivered)
	}
	if totals[0]+totals[1] != 1 {
		t.Fatalf("dispatchers processed %d entries total, want 1 (one claims, the other skips the locked row)", totals[0]+totals[1])
	}
}

// TestIdempotencyDoRunsOnceCachesResult is the AN-5 core (SPINE-012): Do runs fn
// once per (tenant, key) and returns the recorded result on a replay without
// re-running fn.
func TestIdempotencyDoRunsOnceCachesResult(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)

	runs := 0
	fn := func(context.Context) ([]byte, error) {
		runs++
		return []byte("result-v1"), nil
	}
	first, err := idem.Do(ctx, tenantA, "k1", fn)
	if err != nil {
		t.Fatal(err)
	}
	second, err := idem.Do(ctx, tenantA, "k1", fn)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("fn ran %d times, want 1 (replay returns the cached result)", runs)
	}
	if string(first) != "result-v1" || string(second) != "result-v1" {
		t.Fatalf("results = %q / %q, want both result-v1", first, second)
	}
}

// TestIdempotencyDoDoesNotCacheFailures is the failure-not-cached path (SPINE-012):
// when fn fails, the claim rolls back so a later retry is free to run fn again and
// succeed.
func TestIdempotencyDoDoesNotCacheFailures(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)

	attempt := 0
	fn := func(context.Context) ([]byte, error) {
		attempt++
		if attempt == 1 {
			return nil, errors.New("transient")
		}
		return []byte("ok"), nil
	}
	if _, err := idem.Do(ctx, tenantA, "k2", fn); err == nil {
		t.Fatal("first Do should surface fn's error")
	}
	out, err := idem.Do(ctx, tenantA, "k2", fn)
	if err != nil {
		t.Fatalf("retry after a failed attempt should run fn again and succeed, got %v", err)
	}
	if string(out) != "ok" {
		t.Fatalf("retry result = %q, want ok", out)
	}
	if attempt != 2 {
		t.Fatalf("fn ran %d times, want 2 (a failed attempt is not cached, so the retry re-runs)", attempt)
	}
}

// TestIdempotencyDoIsTenantScoped proves the AN-1 confinement: the SAME key in two
// tenants is two independent operations (RLS keys on tenant_id), so both run.
func TestIdempotencyDoIsTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	// Both tenants must exist for any FK-free idempotency_keys write; the table has
	// no FK to tenants, so a bare insert is fine, but we register them for realism.
	mustRegisterTenant(t, s, tenantA)
	mustRegisterTenant(t, s, tenantB)

	runs := map[string]int{}
	mk := func(tag string) func(context.Context) ([]byte, error) {
		return func(context.Context) ([]byte, error) { runs[tag]++; return []byte(tag), nil }
	}
	if _, err := idem.Do(ctx, tenantA, "shared", mk("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := idem.Do(ctx, tenantB, "shared", mk("B")); err != nil {
		t.Fatal(err)
	}
	if runs["A"] != 1 || runs["B"] != 1 {
		t.Fatalf("runs = %v, want each tenant's op to run once (key is tenant-scoped)", runs)
	}
}

// mustRegisterTenant inserts a tenant row directly (system role) so tenant-scoped
// writes have a parent where needed.
func mustRegisterTenant(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if err := s.UpsertTenant(context.Background(), store.Tenant{TenantID: id, Name: "t-" + id}); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
}
