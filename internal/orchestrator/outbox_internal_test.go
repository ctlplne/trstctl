package orchestrator_test

import (
	"context"
	"errors"
	"strings"
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

func TestOutboxRetryJitterDesynchronizesSameDestinationRows(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	jitters := []time.Duration{125 * time.Millisecond, 375 * time.Millisecond}
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return time.Second }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration {
			if len(jitters) == 0 {
				t.Fatal("retry jitter called more times than expected")
			}
			next := jitters[0]
			jitters = jitters[1:]
			return next
		}),
		orchestrator.WithCircuitBreaker(10, time.Minute),
	)
	firstID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "jitter-1", Payload: []byte(`{}`),
	})
	secondID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "jitter-2", Payload: []byte(`{}`),
	})

	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("webhook unavailable")
	}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("Dispatch processed %d rows, want both due rows", n)
	}

	nextAttempts := nextAttemptTimes(t, s, firstID, secondID)
	if !nextAttempts[firstID].Equal(now.Add(125 * time.Millisecond)) {
		t.Fatalf("first next_attempt_at = %s, want %s", nextAttempts[firstID], now.Add(125*time.Millisecond))
	}
	if !nextAttempts[secondID].Equal(now.Add(375 * time.Millisecond)) {
		t.Fatalf("second next_attempt_at = %s, want %s", nextAttempts[secondID], now.Add(375*time.Millisecond))
	}
	if nextAttempts[firstID].Equal(nextAttempts[secondID]) {
		t.Fatal("same-destination retries landed on the same next_attempt_at; jitter must desynchronize them")
	}
}

func TestOutboxOpenCircuitPreventsClaimsUntilHalfOpenProbe(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithCircuitBreaker(1, time.Minute),
	)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "circuit-1", Payload: []byte(`{}`),
	})
	secondID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "circuit-2", Payload: []byte(`{}`),
	})

	failures := 0
	failThenSucceed := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		failures++
		if failures == 1 {
			return errors.New("webhook down")
		}
		return nil
	})
	if n, err := ob.Dispatch(ctx, failThenSucceed); err != nil || n != 1 {
		t.Fatalf("first dispatch n=%d err=%v, want one failed probe", n, err)
	}
	snapshots := ob.CircuitStates()
	if len(snapshots) != 1 || snapshots[0].State != orchestrator.CircuitOpen {
		t.Fatalf("circuit snapshots after failure = %+v, want one open circuit", snapshots)
	}

	if n, err := ob.Dispatch(ctx, failThenSucceed); err != nil || n != 0 {
		t.Fatalf("open-circuit dispatch n=%d err=%v, want no claim before probe window", n, err)
	}
	rec, err := ob.Get(ctx, tenantA, secondID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Attempts != 0 || rec.Status != "pending" {
		t.Fatalf("second row after open circuit = {status:%q attempts:%d}, want untouched pending row", rec.Status, rec.Attempts)
	}

	now = now.Add(time.Minute + time.Nanosecond)
	if n, err := ob.Dispatch(ctx, failThenSucceed); err != nil || n != 2 {
		t.Fatalf("half-open dispatch n=%d err=%v, want the successful probe plus the next queued row", n, err)
	}
	rec, err = ob.Get(ctx, tenantA, secondID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 1 {
		t.Fatalf("second row after half-open probe = {status:%q attempts:%d}, want delivered/1", rec.Status, rec.Attempts)
	}
	snapshots = ob.CircuitStates()
	if len(snapshots) != 1 || snapshots[0].State != orchestrator.CircuitClosed || snapshots[0].Failures != 0 {
		t.Fatalf("circuit snapshots after successful probe = %+v, want closed/reset circuit", snapshots)
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

// TestDispatchOneSkipLockedDoesNotDoubleDeliver is the claim guarantee
// (SPINE-012): two dispatchers sweeping the same single due entry concurrently
// must deliver it exactly once between them, never twice. One leases the row; the
// other sees no pending copy and finds nothing.
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

// TestOutboxLeasesDoNotStarveUnrelatedTenants is the SPINE-002 acceptance: a
// slow destination for tenant A must not hold a database row lock through the
// external call, and another outbox worker must be able to deliver tenant B's fast
// destination while tenant A is still blocked.
func TestOutboxLeasesDoNotStarveUnrelatedTenants(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
		orchestrator.WithMaxInFlightPerDestination(1),
		orchestrator.WithMaxInFlightPerTenant(1),
		orchestrator.WithWorkerID("fairness-test"),
	)

	slowID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "slow-ca", IdempotencyKey: "slow-1", Payload: []byte(`{}`),
	})
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "slow-ca", IdempotencyKey: "slow-2", Payload: []byte(`{}`),
	})
	fastID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantB, Destination: "fast-webhook", IdempotencyKey: "fast-1", Payload: []byte(`{}`),
	})

	slowEntered := make(chan struct{})
	releaseSlow := make(chan struct{})
	fastDelivered := make(chan struct{})
	var slowOnce, fastOnce sync.Once
	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		switch m.Destination {
		case "slow-ca":
			slowOnce.Do(func() { close(slowEntered) })
			select {
			case <-releaseSlow:
				return errors.New("slow destination still unavailable")
			case <-ctx.Done():
				return ctx.Err()
			}
		case "fast-webhook":
			fastOnce.Do(func() { close(fastDelivered) })
			return nil
		default:
			t.Fatalf("unexpected destination %q", m.Destination)
			return nil
		}
	})

	errs := make(chan error, 2)
	go func() {
		_, err := ob.Dispatch(ctx, handler)
		errs <- err
	}()

	select {
	case <-slowEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("slow outbox handler was not entered")
	}
	assertOutboxRowNotLocked(t, s, slowID)

	go func() {
		n, err := ob.Dispatch(ctx, handler)
		if err == nil && n == 0 {
			err = errors.New("second dispatcher did not process tenant B's fast row")
		}
		errs <- err
	}()

	select {
	case <-fastDelivered:
	case <-time.After(500 * time.Millisecond):
		close(releaseSlow)
		t.Fatal("tenant B fast destination was starved behind tenant A slow destination")
	}

	close(releaseSlow)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("dispatch %d: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("dispatch %d did not return", i)
		}
	}

	rec, err := ob.Get(ctx, tenantB, fastID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" {
		t.Fatalf("tenant B fast row status = %q, want delivered", rec.Status)
	}
}

// TestOutboxDeliveryTimeoutRetriesAndDrainsUnrelatedDestination proves that a
// wedged external destination spends only one bounded message deadline on an
// outbox worker. The timed-out row is returned to pending with backoff, while an
// unrelated tenant/destination still drains in the same sweep.
func TestOutboxDeliveryTimeoutRetriesAndDrainsUnrelatedDestination(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
		orchestrator.WithDeliveryTimeout(25*time.Millisecond),
		orchestrator.WithMaxInFlightPerDestination(1),
		orchestrator.WithMaxInFlightPerTenant(1),
		orchestrator.WithWorkerID("timeout-test"),
	)

	slowID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "timeout-slow-1", Payload: []byte(`{}`),
	})
	fastID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantB, Destination: "notification.webhook", IdempotencyKey: "timeout-fast-1", Payload: []byte(`{}`),
	})

	slowEntered := make(chan struct{})
	fastDelivered := make(chan struct{})
	var slowOnce, fastOnce sync.Once
	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		switch m.Destination {
		case "connector.deploy":
			slowOnce.Do(func() { close(slowEntered) })
			<-ctx.Done()
			return ctx.Err()
		case "notification.webhook":
			fastOnce.Do(func() { close(fastDelivered) })
			return nil
		default:
			t.Fatalf("unexpected destination %q", m.Destination)
			return nil
		}
	})

	start := time.Now()
	n, err := ob.Dispatch(ctx, handler)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("Dispatch processed %d rows, want 2 (slow timeout plus unrelated fast delivery)", n)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Dispatch took %v, want it bounded by the per-message delivery timeout", elapsed)
	}

	select {
	case <-slowEntered:
	default:
		t.Fatal("slow destination was never invoked")
	}
	select {
	case <-fastDelivered:
	default:
		t.Fatal("unrelated destination did not drain after the slow timeout")
	}

	slow, err := ob.Get(ctx, tenantA, slowID)
	if err != nil {
		t.Fatal(err)
	}
	if slow.Status != "pending" || slow.Attempts != 1 || !strings.Contains(slow.LastError, "context deadline exceeded") {
		t.Fatalf("slow row = {status:%q attempts:%d last_error:%q}, want pending/1/context deadline exceeded",
			slow.Status, slow.Attempts, slow.LastError)
	}

	fast, err := ob.Get(ctx, tenantB, fastID)
	if err != nil {
		t.Fatal(err)
	}
	if fast.Status != "delivered" {
		t.Fatalf("fast row status = %q, want delivered", fast.Status)
	}
}

func assertOutboxRowNotLocked(t *testing.T, s *store.Store, id int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock probe: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var got int64
	if err := tx.QueryRow(ctx, `SELECT id FROM outbox WHERE id = $1 FOR UPDATE NOWAIT`, id).Scan(&got); err != nil {
		t.Fatalf("outbox row %d is still locked while handler is sleeping: %v", id, err)
	}
	if got != id {
		t.Fatalf("lock probe got row %d, want %d", got, id)
	}
}

func nextAttemptTimes(t *testing.T, s *store.Store, ids ...int64) map[int64]time.Time {
	t.Helper()
	out := make(map[int64]time.Time, len(ids))
	for _, id := range ids {
		var next time.Time
		if err := s.SystemPool().QueryRow(context.Background(), `SELECT next_attempt_at FROM outbox WHERE id = $1`, id).Scan(&next); err != nil {
			t.Fatalf("read next_attempt_at for row %d: %v", id, err)
		}
		out[id] = next
	}
	return out
}

// TestOutboxExpiredLeaseIsReclaimed proves a worker crash after claim but before
// finalize does not strand an outbox row forever: the next dispatcher returns the
// expired lease to pending and redelivers it with the same idempotency key.
func TestOutboxExpiredLeaseIsReclaimed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s, orchestrator.WithWorkerID("rescuer"))
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "lease-retry-1", Payload: []byte(`{}`),
	})
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox
		    SET status = 'processing',
		        worker_id = 'dead-worker',
		        lease_until = now() - interval '1 second',
		        attempts = 1
		  WHERE id = $1`, id); err != nil {
		t.Fatalf("seed expired lease: %v", err)
	}

	var delivered []orchestrator.Message
	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		delivered = append(delivered, m)
		return nil
	}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 1 || len(delivered) != 1 {
		t.Fatalf("dispatch after expired lease = %d deliveries=%d, want exactly 1", n, len(delivered))
	}
	if delivered[0].IdempotencyKey != "lease-retry-1" {
		t.Fatalf("redelivered key = %q, want lease-retry-1", delivered[0].IdempotencyKey)
	}
	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 2 {
		t.Fatalf("rec = {status:%q attempts:%d}, want delivered/2", rec.Status, rec.Attempts)
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
