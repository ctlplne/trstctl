package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// TestOutboxTickShedUnderSaturationPreservesWork is the CODE-007 regression guard:
// the outbox dispatcher tick is routed through the outbox bulkhead pool, and when
// that pool is saturated the tick is SHED (the rejected Submit is intentionally
// ignored) rather than blocking or piling up sweeps (AN-7). This is documented,
// intentional backpressure — NOT a dropped event — because every outbox row is
// claimed FOR UPDATE SKIP LOCKED and persists, so the next unsaturated tick
// delivers it.
//
// The test proves both halves of that contract against the real embedded stack:
//
//  1. With the outbox pool's only worker occupied, dispatchOnce returns PROMPTLY
//     (it does not block on the full pool) and the handler is NOT invoked — the
//     tick was shed — and the enqueued row is STILL pending (no work was lost).
//  2. After the pool frees up, a subsequent dispatchOnce delivers the SAME
//     persisted row exactly once.
//
// A regression that made the shed blocking (dropping the select/default), or that
// dropped the row on a shed, fails here.
func TestOutboxTickShedUnderSaturationPreservesWork(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	dsn, stopPG, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: freeTCPPort(t)})
	if err != nil {
		t.Fatalf("start bundled postgres: %v", err)
	}
	t.Cleanup(func() { _ = stopPG() })

	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	// A counting handler signals each delivery so the test can wait for the
	// asynchronous pool worker to finish (deliveries run inside the outbox pool).
	var delivered atomic.Int64
	deliveredCh := make(chan struct{}, 4)
	handler := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		delivered.Add(1)
		deliveredCh <- struct{}{}
		return nil
	})

	// A single-worker, zero-queue outbox pool so occupying the worker makes every
	// further Submit reject (the saturation we want to shed on). The API pool is
	// healthy and irrelevant here.
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 2, Queue: 8},
		bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 1, Queue: 0},
	)
	srv, err := Build(ctx, Deps{Store: st, Log: log, Bulkhead: set, OutboxHandler: handler})
	if err != nil {
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Seed a tenant and enqueue one outbox row (a benign destination the handler
	// just acknowledges) in the tenant's RLS context, exactly as a state change
	// would (AN-6).
	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "shed-test"}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, e := srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    "connector.deploy", // acknowledged by the handler
			IdempotencyKey: "shed-row-1",
			Payload:        []byte(`{}`),
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue outbox row: %v", err)
	}

	pending := func() int {
		recs, perr := srv.outbox.Pending(ctx, tenantID)
		if perr != nil {
			t.Fatalf("Pending: %v", perr)
		}
		return len(recs)
	}
	if pending() != 1 {
		t.Fatalf("setup: outbox should have 1 pending row, got %d", pending())
	}

	// --- Phase 1: saturate the outbox pool, then tick. The tick must be shed. ---
	release := make(chan struct{})
	occupied := make(chan struct{})
	for {
		if err := set.Pool(bulkhead.SubsystemOutbox).Submit(func() { close(occupied); <-release }); err == nil {
			break
		}
	}
	<-occupied // the only outbox worker is now busy and blocked

	// dispatchOnce must return promptly despite the full pool (it sheds via the
	// non-blocking Submit). If it blocked, this goroutine would hang; we bound it.
	done := make(chan struct{})
	go func() { srv.dispatchOnce(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("dispatchOnce blocked on a saturated outbox pool; the tick must be shed, not block (AN-7, CODE-007)")
	}

	// The shed tick delivered nothing and lost nothing: handler not called, row
	// still pending. (Give a brief window to rule out an erroneous async delivery.)
	select {
	case <-deliveredCh:
		close(release)
		t.Fatal("a shed tick delivered an outbox row; under saturation the tick must shed without delivering")
	case <-time.After(150 * time.Millisecond):
	}
	if got := delivered.Load(); got != 0 {
		close(release)
		t.Fatalf("handler ran %d times during the shed; want 0", got)
	}
	if pending() != 1 {
		close(release)
		t.Fatalf("the shed dropped the work: %d pending rows, want 1 (the row must persist for the next tick)", pending())
	}

	// --- Phase 2: free the pool; a subsequent tick delivers the persisted row. ---
	close(release) // the occupying worker returns from <-release and the pool drains

	// Tick on the dispatcher's real cadence until the persisted row is delivered.
	// The first tick(s) may still be shed if the freed worker hasn't returned yet —
	// that is exactly the "next tick retries" contract — so we retry within a bound
	// rather than assuming a single tick lands.
	deadline := time.After(5 * time.Second)
	for {
		srv.dispatchOnce(ctx)
		select {
		case <-deliveredCh:
			goto delivered
		case <-time.After(50 * time.Millisecond):
			// not yet; tick again
		case <-deadline:
			t.Fatal("after the pool freed, the persisted outbox row was never delivered on a later tick (work was lost)")
		}
	}
delivered:
	if got := delivered.Load(); got != 1 {
		t.Fatalf("handler ran %d times after recovery; want exactly 1 (the persisted row, delivered once)", got)
	}
}
