// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// DP2-056: the durable projection tail is a bounded system worker. A tenant burst
// that holds every request-pool connection (correctly shed with 503s) must not
// starve it: the tail keeps applying on the store's reserved pool, so readiness
// never reports "projection tail failed" for the duration of the burst. On the
// starting candidate the tail acquired from the request pool, timed out after the
// acquire window and logged "projection tail worker stopped; retrying".
func TestTailWorkerAppliesWhileTheRequestPoolIsSaturated(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proj := projections.New(s)
	worker := projections.NewTailWorker(log, proj, nil, 50*time.Millisecond)
	runErr := make(chan error, 1)
	go func() { runErr <- worker.Run(ctx) }()
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	waitForCheckpoint(t, s, 1, 20*time.Second)

	// Hold every request-pool connection for the rest of the test.
	held := holdEveryConnection(t, s.SystemPool())
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	if len(held) < 4 {
		t.Fatalf("held only %d request-pool connections; the pool must be saturated for this guard", len(held))
	}

	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Data: ownerCreated("00000000-0000-0000-0000-0000000000c2", "tailed-under-load"),
	}); err != nil {
		t.Fatal(err)
	}
	// Well inside the request pool's 10 s acquire window: the tail must not be
	// waiting on that pool at all.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := held[0].QueryRow(ctx, `SELECT count(*) FROM owners WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			select {
			case err := <-runErr:
				t.Fatalf("tail worker stopped while the request pool was saturated: %v", err)
			default:
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-runErr:
		t.Fatalf("tail worker stopped instead of applying on the reserved pool: %v", err)
	default:
	}
	t.Fatalf("out-of-band event not projected within 8 s while the request pool was saturated")
}

func waitForCheckpoint(t *testing.T, s *store.Store, want uint64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		seq, err := s.ProjectionCheckpoint(store.WithReservedPool(context.Background()))
		if err != nil {
			t.Fatal(err)
		}
		if seq >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("projection checkpoint did not reach %d within %s", want, within)
}

func holdEveryConnection(t *testing.T, pool *pgxpool.Pool) []*pgxpool.Conn {
	t.Helper()
	var held []*pgxpool.Conn
	for i := 0; i < 64; i++ {
		acquireCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := pool.Acquire(acquireCtx)
		cancel()
		if err != nil {
			break
		}
		held = append(held, c)
	}
	return held
}
