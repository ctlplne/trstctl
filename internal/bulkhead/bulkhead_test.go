package bulkhead_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
)

// waitTimeout fails the test if wg does not complete within d.
func waitTimeout(t *testing.T, wg *sync.WaitGroup, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("timed out waiting for pool tasks")
	}
}

func waitCompleted(t *testing.T, p *bulkhead.Pool, want int64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if got := p.Stats().Completed; got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("completed %d tasks, want >= %d", p.Stats().Completed, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPoolRunsSubmittedWork(t *testing.T) {
	p := bulkhead.New(bulkhead.Config{Name: "x", Workers: 3, Queue: 16})
	defer p.Close()

	var n atomic.Int64
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		if err := p.Submit(func() { n.Add(1); wg.Done() }); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	waitTimeout(t, &wg, 2*time.Second)
	if got := n.Load(); got != 10 {
		t.Errorf("ran %d tasks, want 10", got)
	}
}

// TestPoolFastRejectsWhenSaturated is the AN-7 acceptance: a saturated pool
// rejects fast with a structured error rather than blocking the caller.
func TestPoolFastRejectsWhenSaturated(t *testing.T) {
	p := bulkhead.New(bulkhead.Config{Name: "api", Workers: 1, Queue: 1})
	defer p.Close()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	if err := p.Submit(func() { started <- struct{}{}; <-release }); err != nil {
		t.Fatalf("submit (occupy worker): %v", err)
	}
	<-started // the only worker is now busy and blocked
	if err := p.Submit(func() { <-release }); err != nil {
		t.Fatalf("submit (fill queue): %v", err)
	}

	// The pool is now saturated. The next submit must reject — fast.
	start := time.Now()
	err := p.Submit(func() { t.Error("a rejected task must never run") })
	elapsed := time.Since(start)

	var rej *bulkhead.Rejected
	if !errors.As(err, &rej) {
		t.Fatalf("submit error = %v, want *bulkhead.Rejected", err)
	}
	if !errors.Is(err, bulkhead.ErrRejected) {
		t.Error("errors.Is(err, ErrRejected) = false, want true")
	}
	if rej.Pool != "api" || rej.Reason != bulkhead.ReasonFull || rej.Capacity != 1 {
		t.Errorf("rejection = %+v, want api/queue full/capacity 1", rej)
	}
	if !rej.Retryable() {
		t.Error("a full-queue rejection should be Retryable")
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Submit blocked for %v; backpressure must reject fast", elapsed)
	}

	close(release)
}

// TestSetIsolatesSubsystems is the AN-7 isolation acceptance: saturating one
// subsystem's pool does not block or starve another's.
func TestSetIsolatesSubsystems(t *testing.T) {
	set := bulkhead.NewSet(
		bulkhead.Config{Name: "slow", Workers: 1, Queue: 1},
		bulkhead.Config{Name: "fast", Workers: 4, Queue: 256},
	)
	defer set.Close()

	// Jam "slow": occupy its single worker and fill its one-slot queue.
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	if err := set.Submit("slow", func() { started <- struct{}{}; <-release }); err != nil {
		t.Fatalf("slow submit (worker): %v", err)
	}
	<-started
	if err := set.Submit("slow", func() { <-release }); err != nil {
		t.Fatalf("slow submit (queue): %v", err)
	}
	// Further work to "slow" is rejected.
	if err := set.Submit("slow", func() {}); !errors.Is(err, bulkhead.ErrRejected) {
		t.Fatalf("saturated slow pool error = %v, want ErrRejected", err)
	}

	// Meanwhile "fast" accepts and completes a full load, unaffected.
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		if err := set.Submit("fast", func() { wg.Done() }); err != nil {
			t.Fatalf("fast submit %d: %v (isolation broken: slow starved fast)", i, err)
		}
	}
	waitTimeout(t, &wg, 2*time.Second)
	waitCompleted(t, set.Pool("fast"), N, 2*time.Second)
	if set.Pool("slow").Stats().Rejected == 0 {
		t.Error("slow recorded no rejections; expected backpressure under saturation")
	}

	close(release) // let slow drain so Close returns
}

func TestSetSubmitUnknownSubsystem(t *testing.T) {
	set := bulkhead.NewSet(bulkhead.Config{Name: "api", Workers: 1, Queue: 1})
	defer set.Close()

	err := set.Submit("nope", func() { t.Error("must not run") })
	var rej *bulkhead.Rejected
	if !errors.As(err, &rej) || rej.Reason != bulkhead.ReasonUnknown {
		t.Errorf("unknown-subsystem submit = %v, want *Rejected/unknown subsystem", err)
	}
	if rej.Retryable() {
		t.Error("an unknown subsystem is a permanent rejection, not retryable")
	}
}

func TestPoolCloseDrainsThenRejects(t *testing.T) {
	p := bulkhead.New(bulkhead.Config{Name: "x", Workers: 2, Queue: 10})

	var n atomic.Int64
	for i := 0; i < 5; i++ {
		if err := p.Submit(func() { n.Add(1) }); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	p.Close() // drains queued work and waits for workers

	if got := n.Load(); got != 5 {
		t.Errorf("completed %d, want all 5 drained before Close returned", got)
	}
	err := p.Submit(func() { t.Error("must not run after Close") })
	var rej *bulkhead.Rejected
	if !errors.As(err, &rej) || rej.Reason != bulkhead.ReasonClosed {
		t.Errorf("post-close submit = %v, want *Rejected/pool closed", err)
	}
	if rej.Retryable() {
		t.Error("a closed pool is a permanent rejection, not retryable")
	}
}

// TestPoolRecoversFromPanickingTask shows fault isolation: one task panicking
// does not tear down the worker or the pool.
func TestPoolRecoversFromPanickingTask(t *testing.T) {
	p := bulkhead.New(bulkhead.Config{Name: "x", Workers: 1, Queue: 4})
	defer p.Close()

	if err := p.Submit(func() { panic("boom") }); err != nil {
		t.Fatalf("submit (panicking): %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	if err := p.Submit(func() { wg.Done() }); err != nil {
		t.Fatalf("submit (after panic): %v", err)
	}
	waitTimeout(t, &wg, 2*time.Second) // the pool survived the panic

	if got := p.Stats().Panicked; got != 1 {
		t.Errorf("Panicked = %d, want 1", got)
	}
}
