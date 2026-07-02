package server

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
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
