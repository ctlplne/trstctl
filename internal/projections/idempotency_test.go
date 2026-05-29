package projections_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"certctl.io/certctl/internal/app"
	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/orchestrator"
)

// TestIdempotencyReplayReturnsCached is the AN-5 acceptance: replaying a key
// returns the original result without re-executing the operation.
func TestIdempotencyReplayReturnsCached(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)

	var calls int64
	op := func(context.Context) ([]byte, error) {
		atomic.AddInt64(&calls, 1)
		return []byte("first-result"), nil
	}

	first, err := idem.Do(ctx, tenantA, "key-1", op)
	if err != nil {
		t.Fatalf("first Do: %v", err)
	}
	second, err := idem.Do(ctx, tenantA, "key-1", op)
	if err != nil {
		t.Fatalf("replay Do: %v", err)
	}

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("operation executed %d times, want exactly 1 (replay must not re-execute)", got)
	}
	if string(first) != "first-result" || string(second) != "first-result" {
		t.Errorf("results = %q, %q; want both %q (replay must return the cached result)",
			first, second, "first-result")
	}
}

// TestIdempotencyConcurrentOneEffect is the AN-5 concurrency acceptance: many
// identical requests for the same key produce exactly one effect, and all of
// them observe the same result.
func TestIdempotencyConcurrentOneEffect(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)

	var calls int64
	op := func(context.Context) ([]byte, error) {
		atomic.AddInt64(&calls, 1)
		return []byte("the-one-effect"), nil
	}

	const n = 6
	var wg sync.WaitGroup
	results := make([][]byte, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = idem.Do(ctx, tenantA, "concurrent-key", op)
		}(i)
	}
	close(start) // release all goroutines at once
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("operation executed %d times, want exactly 1 (concurrent retries must collapse)", got)
	}
	for i, r := range results {
		if string(r) != "the-one-effect" {
			t.Errorf("goroutine %d result = %q, want %q", i, r, "the-one-effect")
		}
	}
}

// TestRegisterTenantIdempotent is the end-to-end AN-5 acceptance through the app
// service: registering with the same key twice emits exactly one event and
// leaves exactly one tenant in the read model.
func TestRegisterTenantIdempotent(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	svc := app.New(log, s)

	const key = "register-acme-once"
	if err := svc.RegisterTenant(ctx, tenantA, "Acme", key); err != nil {
		t.Fatalf("first RegisterTenant: %v", err)
	}
	if err := svc.RegisterTenant(ctx, tenantA, "Acme", key); err != nil {
		t.Fatalf("replay RegisterTenant: %v", err)
	}

	emitted := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == "tenant.registered" && e.TenantID == tenantA {
			emitted++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if emitted != 1 {
		t.Errorf("emitted %d tenant.registered events, want exactly 1 (idempotent replay)", emitted)
	}

	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].TenantID != tenantA {
		t.Fatalf("read model = %v, want a single Acme tenant", tenants)
	}
}
