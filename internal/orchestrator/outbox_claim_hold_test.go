// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

// slowSweeps runs a first sweep of ob whose receiver is slow, then, once that
// delivery has begun, keeps sweeping the same outbox from a second goroutine
// for the given time, as a family pool with more than one worker does. It
// returns how many deliveries the receiver saw and the sweeps' errors.
func slowSweeps(t *testing.T, ob *orchestrator.Outbox, receiver func(ctx context.Context, call int32) error, sweepFor, every time.Duration) (int32, []error) {
	t.Helper()
	ctx := context.Background()
	var calls atomic.Int32
	started := make(chan struct{}, 8)
	h := orchestrator.HandlerFunc(func(ctx context.Context, _ orchestrator.Message) error {
		call := calls.Add(1)
		started <- struct{}{}
		return receiver(ctx, call)
	})
	var mu sync.Mutex
	var errs []error
	record := func(err error) {
		if err != nil {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}
	}
	first := make(chan struct{})
	go func() {
		defer close(first)
		_, err := ob.Dispatch(ctx, h)
		record(err)
	}()
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("the first sweep never began its delivery")
	}
	for end := time.Now().Add(sweepFor); time.Now().Before(end); time.Sleep(every) {
		_, err := ob.Dispatch(ctx, h)
		record(err)
	}
	<-first
	return calls.Load(), errs
}

// TestOutboxLeaseFollowsALiveDeliveryA98L1: a family pool sweeps its scope
// with more than one goroutine of one outbox. A delivery slower than the
// claim's lease (a slow receiver, a busy datastore between claim and
// finalize) lost its row to the next sweep's lease recovery, which delivered
// it a second time: under load a tenant PagerDuty test notification reached
// its receiver twice (A98-L1). The lease now follows the delivering sweep:
// with a 300 ms lease and a receiver that takes four leases, a second sweep
// running throughout finds nothing to recover, and the row is delivered
// once, on its first attempt.
func TestOutboxLeaseFollowsALiveDeliveryA98L1(t *testing.T) {
	s := newStore(t)
	const lease = 300 * time.Millisecond
	ob := orchestrator.NewOutbox(s, orchestrator.WithLeaseTTL(lease), orchestrator.WithDeliveryTimeout(10*lease), orchestrator.WithWorkerID("a98l1-pool"))
	id := enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "webhook", IdempotencyKey: "a98l1-slow", Payload: []byte(`{}`)})
	calls, errs := slowSweeps(t, ob, func(ctx context.Context, _ int32) error {
		select {
		case <-time.After(4 * lease):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, 6*lease, lease/5)
	if calls != 1 {
		t.Fatalf("deliveries = %d, want 1 (sweep errors: %v)", calls, errs)
	}
	if len(errs) != 0 {
		t.Fatalf("sweep errors: %v", errs)
	}
	rec, err := ob.Get(context.Background(), tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 1 {
		t.Fatalf("row status=%q attempts=%d, want delivered on its first attempt", rec.Status, rec.Attempts)
	}
}

// TestOutboxHoldEndsAtTheDeliveryDeadlinePlusOneLeaseA98L1: the hold is
// bounded. A receiver that ignores its deadline and hangs keeps its row only
// until the claim's delivery deadline plus one lease; then the lease runs
// out, recovery hands the row to the next sweep, which delivers it, and the
// hung attempt's late finalize finds its claim gone.
func TestOutboxHoldEndsAtTheDeliveryDeadlinePlusOneLeaseA98L1(t *testing.T) {
	s := newStore(t)
	const lease = 200 * time.Millisecond
	ob := orchestrator.NewOutbox(s, orchestrator.WithLeaseTTL(lease), orchestrator.WithDeliveryTimeout(lease), orchestrator.WithWorkerID("a98l1-hung"))
	id := enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "webhook", IdempotencyKey: "a98l1-hung", Payload: []byte(`{}`)})
	calls, errs := slowSweeps(t, ob, func(_ context.Context, call int32) error {
		if call == 1 {
			time.Sleep(8 * lease) // hangs, deaf to its deadline
		}
		return nil
	}, 6*lease, lease/4)
	if calls != 2 {
		t.Fatalf("deliveries = %d, want 2: the hung claim's row recovered once its hold ended (errors: %v)", calls, errs)
	}
	lost := false
	for _, err := range errs {
		lost = lost || (err != nil && !errors.Is(err, context.DeadlineExceeded))
	}
	if !lost {
		t.Fatalf("the hung attempt's finalize reported nothing (errors: %v)", errs)
	}
	rec, err := ob.Get(context.Background(), tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 2 {
		t.Fatalf("row status=%q attempts=%d, want delivered on the recovered attempt", rec.Status, rec.Attempts)
	}
}
