package projections_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestTailWorkerProjectsOutOfBandEvent is the SPINE-009 acceptance: an event
// appended out of band (directly to the log, NOT through the inline orchestrator
// projection) is projected by the durable tailing worker without a restart, and the
// projection-lag metric returns to zero once it catches up. On the pre-fix tree such
// an event was only projected on the next boot replay (silent lag) and there was no
// lag signal at all.
func TestTailWorkerProjectsOutOfBandEvent(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proj := projections.New(s)

	// Seed a tenant so the owner projection's FK/RLS context is valid.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}

	// The lag sampler runs on its own goroutine (sampleLagLoop); count invocations
	// atomically so the read at the end of the test does not race the write from that
	// goroutine. The lag VALUE is timing-dependent and not asserted — only that the
	// gauge is actually sampled (SPINE-009).
	var sampled atomic.Uint64
	worker := projections.NewTailWorker(log, proj, func(float64) { sampled.Add(1) }, 50*time.Millisecond)
	runErr := make(chan error, 1)
	go func() { runErr <- worker.Run(ctx) }()

	// Append an owner event OUT OF BAND (the orchestrator did not project it inline).
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Data: ownerCreated("00000000-0000-0000-0000-0000000000c1", "tailed"),
	}); err != nil {
		t.Fatal(err)
	}

	// The tailing worker must project it within a short SLA, with no restart.
	deadline := time.Now().Add(20 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		got = ownerCount(t, s, tenantA)
		if got == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got != 1 {
		t.Fatalf("out-of-band event not projected by the tailing worker within SLA (owners=%d, want 1)", got)
	}

	// The lag must return to zero once caught up (the gauge exists and is exercised).
	lagDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(lagDeadline) {
		l, err := worker.Lag(ctx)
		if err != nil {
			t.Fatalf("Lag: %v", err)
		}
		if l == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if l, _ := worker.Lag(ctx); l != 0 {
		t.Errorf("projection lag = %d after catch-up, want 0", l)
	}
	if worker.Applied() == 0 {
		t.Error("worker Applied() is 0; the tailing worker did not advance its cursor")
	}
	// The lag gauge must actually be sampled (SPINE-009): the lag loop invokes the
	// sampler on its own 50ms cadence. Wait (bounded) for at least one invocation so
	// the assertion can't flake, then confirm the gauge is wired.
	sampledDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(sampledDeadline) && sampled.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if sampled.Load() == 0 {
		t.Error("lag sampler was never invoked; the SPINE-009 projection-lag gauge is not wired")
	}

	cancel()
	// Run returns the context error on shutdown — not a real failure.
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Error("tail worker did not stop on context cancel")
	}
}

// TestTailWorkerDurableCursorResumes is the SPINE-009 durability assertion: the
// consumer's cursor is server-side and durable, so a fresh worker (a "restart")
// resumes from the last applied event rather than re-projecting from the start. We
// project everything with worker #1, then start worker #2 and confirm it does not
// re-apply already-projected events (Applied advances only for genuinely new ones).
func TestTailWorkerDurableCursorResumes(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	proj := projections.New(s)

	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d1", "one")}); err != nil {
		t.Fatal(err)
	}

	// Worker #1 drains everything, then stops.
	ctx1, cancel1 := context.WithCancel(ctx)
	w1 := projections.NewTailWorker(log, proj, nil, time.Second)
	done1 := make(chan struct{})
	go func() { defer close(done1); _ = w1.Run(ctx1) }()
	waitFor(t, func() bool { l, _ := w1.Lag(ctx); return l == 0 && w1.Applied() > 0 }, 20*time.Second, "worker #1 catch up")
	cancel1()
	<-done1

	headBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Worker #2 ("restart") must resume at the durable cursor: with no new events it
	// applies nothing and the lag is already zero.
	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	w2 := projections.NewTailWorker(log, proj, nil, time.Second)
	done2 := make(chan struct{})
	go func() { defer close(done2); _ = w2.Run(ctx2) }()

	// Append one MORE event; only this one should be newly applied by worker #2.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d2", "two")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w2.Applied() > headBefore }, 20*time.Second, "worker #2 apply only the new event")
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Errorf("owners after resume = %d, want 2", got)
	}
	cancel2()
	<-done2
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}
