package projections_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/idemgc"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
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
	defer svc.Close()

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

// TestIdempotencyPurgeBoundsTable is the SPINE-002 acceptance: the background
// sweep reclaims completed idempotency keys older than the retention window so the
// table cannot grow without bound, while keys still inside the window (and any
// in-flight/pending claim) are preserved — so AN-5 still holds within the window.
// Pre-fix there was no DELETE/TTL anywhere, so this would never reclaim a row.
func TestIdempotencyPurgeBoundsTable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	idem := orchestrator.NewIdempotency(s)
	sweeper := idemgc.New(s, 7*24*time.Hour)

	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	recent := time.Now().UTC()
	seedKey := func(key string, completedAt time.Time) {
		if _, err := s.Pool().Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, result, completed_at)
			 VALUES ($1, $2, 'completed', $3, $4)`,
			tenantA, key, []byte("result-"+key), completedAt); err != nil {
			t.Fatalf("seed key %s: %v", key, err)
		}
	}
	for i := 0; i < 20; i++ {
		seedKey(fmt.Sprintf("recent-%d", i), recent)
		seedKey(fmt.Sprintf("old-%d", i), old)
	}
	// A pending (in-flight) key has a NULL completed_at and must never be purged.
	if _, err := s.Pool().Exec(ctx,
		`INSERT INTO idempotency_keys (tenant_id, key, status) VALUES ($1, 'pending-key', 'pending')`,
		tenantA); err != nil {
		t.Fatal(err)
	}

	before, err := sweeper.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before != 41 {
		t.Fatalf("seeded %d keys, want 41", before)
	}

	// A 7-day retention expires the 30-day-old keys; recent + pending survive.
	reclaimed, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if reclaimed != 20 {
		t.Fatalf("reclaimed %d rows, want 20 (the old keys)", reclaimed)
	}
	after, err := sweeper.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != 21 {
		t.Fatalf("after sweep %d keys, want 21 (20 recent + 1 pending) — table must be bounded", after)
	}

	// AN-5 within the window: a retry of a still-young key returns its cached result
	// without re-executing the operation.
	got, err := idem.Do(ctx, tenantA, "recent-0", func(context.Context) ([]byte, error) {
		t.Fatal("operation ran for a cached key — AN-5 broken within the retention window")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Do(recent-0): %v", err)
	}
	if string(got) != "result-recent-0" {
		t.Fatalf("cached result = %q, want result-recent-0", got)
	}

	// The sweep is idempotent: a second pass reclaims nothing (the bound holds).
	r2, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r2 != 0 {
		t.Fatalf("second sweep reclaimed %d, want 0", r2)
	}
}

// TestIdempotencyPurgeIndexUsed asserts the sweep's predicate uses the partial
// completed_at index (SPINE-002) rather than a sequential scan, so reclamation
// stays cheap as the table grows. The table is dominated by young keys with a
// small eligible old tail — the steady state under retention, and exactly when the
// index is the cheaper path.
func TestIdempotencyPurgeIndexUsed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	young := time.Now().UTC()
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	for i := 0; i < 2000; i++ {
		if _, err := s.Pool().Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, completed_at)
			 VALUES ($1, $2, 'completed', $3)`,
			tenantA, fmt.Sprintf("young-%d", i), young); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		if _, err := s.Pool().Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, completed_at)
			 VALUES ($1, $2, 'completed', $3)`,
			tenantA, fmt.Sprintf("old-%d", i), old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Pool().Exec(ctx, "ANALYZE idempotency_keys"); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	rows, err := s.Pool().Query(ctx,
		`EXPLAIN SELECT 1 FROM idempotency_keys WHERE completed_at IS NOT NULL AND completed_at < $1`, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan += line + "\n"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "idempotency_keys_completed_at_idx") {
		t.Fatalf("purge predicate did not use the completed_at index; plan:\n%s", plan)
	}
}
