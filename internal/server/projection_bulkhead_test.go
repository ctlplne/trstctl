package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestProjectionTailUsesProjectionBulkhead is the SPINE-005 regression guard: the
// served projection tail must enter the projections bulkhead before it owns the
// durable event-log consumer. If that pool is saturated, the tail start sheds and
// retries instead of bypassing the advertised TRSTCTL_BULKHEAD_PROJECTIONS knobs.
func TestProjectionTailUsesProjectionBulkhead(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 2, Queue: 8},
		bulkhead.Config{Name: bulkhead.SubsystemProjections, Workers: 1, Queue: 0},
	)
	srv, err := Build(ctx, Deps{Store: st, Log: log, Bulkhead: set})
	if err != nil {
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	release := make(chan struct{})
	defer close(release)
	occupied := make(chan struct{})
	for {
		if err := set.Pool(bulkhead.SubsystemProjections).Submit(func() {
			close(occupied)
			<-release
		}); err == nil {
			break
		}
	}
	<-occupied

	tailCtx, cancelTail := context.WithCancel(ctx)
	defer cancelTail()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunProjectionTail(tailCtx)
	}()

	waitForProjectionStats(t, set.Pool(bulkhead.SubsystemProjections), func(st bulkhead.Stats) bool {
		return st.Rejected > 0
	}, 3*time.Second, "projection tail rejection on saturated projections bulkhead")

	cancelTail()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("projection tail did not stop on context cancellation")
	}
}

// TestProjectionTailRetryDoesNotLeakSamplers covers the served retry path for
// SPINE-007: RunProjectionTail reuses the service context across retries, so each
// failed TailWorker.Run invocation must cancel only its own lag sampler.
func TestProjectionTailRetryDoesNotLeakSamplers(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	srv, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	var sampled atomic.Uint64
	var activeSamplers atomic.Int64
	var maxActiveSamplers atomic.Int64
	srv.tailWorker = projections.NewTailWorker(log, projections.New(st), func(float64) {
		sampled.Add(1)
		active := activeSamplers.Add(1)
		recordMaxAtomic(&maxActiveSamplers, active)
		time.Sleep(40 * time.Millisecond)
		activeSamplers.Add(-1)
	}, 10*time.Millisecond)

	tailCtx, cancelTail := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunProjectionTail(tailCtx)
	}()
	t.Cleanup(func() {
		cancelTail()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("projection tail did not stop on context cancellation")
		}
	})

	waitForSamplerCount(t, &sampled, 2, 2*time.Second, "initial projection lag sampling")

	if _, err := log.Append(ctx, events.Event{
		Type:          projections.EventOwnerCreated,
		TenantID:      "11111111-1111-1111-1111-111111111111",
		SchemaVersion: 99, // unknown -> Apply rejects and RunProjectionTail backs off/retries
		Data:          []byte(`{"id":"00000000-0000-0000-0000-0000000000f1","kind":"workload","name":"poison"}`),
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(1700 * time.Millisecond)
	if got := maxActiveSamplers.Load(); got > 1 {
		t.Fatalf("projection tail retry multiplied lag samplers: max active callbacks=%d, want <=1", got)
	}
}

func waitForProjectionStats(t *testing.T, p *bulkhead.Pool, cond func(bulkhead.Stats) bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond(p.Stats()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; final stats: %+v", what, p.Stats())
}

func waitForSamplerCount(t *testing.T, sampled *atomic.Uint64, want uint64, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sampled.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; sampled=%d want>=%d", what, sampled.Load(), want)
}

func recordMaxAtomic(max *atomic.Int64, value int64) {
	for {
		current := max.Load()
		if value <= current {
			return
		}
		if max.CompareAndSwap(current, value) {
			return
		}
	}
}
