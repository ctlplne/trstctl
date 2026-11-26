// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRateLimitTakeShedsLoad is the R2.3 store-level acceptance for the
// PostgreSQL-backed rate limiter: a token bucket of capacity N admits exactly N
// rapid requests and then sheds, reporting a positive retry-after — and each
// tenant has its own isolated bucket (AN-1).
func TestRateLimitTakeShedsLoad(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"

	// Capacity 3, negligible refill within the test window.
	allowed := 0
	for i := 0; i < 5; i++ {
		ok, _, err := st.RateLimitTake(ctx, tenantA, "api", 3, 0.001)
		if err != nil {
			t.Fatalf("RateLimitTake: %v", err)
		}
		if ok {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("admitted %d of 5 rapid requests, want 3 (the bucket capacity)", allowed)
	}

	// A shed request reports when to retry.
	ok, retry, err := st.RateLimitTake(ctx, tenantA, "api", 3, 0.001)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a 7th rapid request should be shed")
	}
	if retry <= 0 {
		t.Errorf("a shed request should report a positive retry-after, got %v", retry)
	}

	// A different tenant has its own fresh bucket (tenant isolation).
	ok, _, err = st.RateLimitTake(ctx, tenantB, "api", 3, 0.001)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("a different tenant must not be limited by another tenant's usage (AN-1)")
	}
}

func TestRateLimitTakeCostBoundsBytesAcrossCalls(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const tenant = "33333333-3333-4333-8333-333333333333"
	for _, cost := range []float64{4, 4, 2} {
		allowed, _, err := st.RateLimitTakeCost(ctx, tenant, "agent:heartbeat-bytes:test", 10, 0, cost)
		if err != nil || !allowed {
			t.Fatalf("cost %.0f admitted=%v err=%v", cost, allowed, err)
		}
	}
	if allowed, _, err := st.RateLimitTakeCost(ctx, tenant, "agent:heartbeat-bytes:test", 10, 0, 1); err != nil || allowed {
		t.Fatalf("bytes beyond budget admitted=%v err=%v", allowed, err)
	}
}

func TestRateLimitFirstUseSerializesConcurrentAgents(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const tenant = "44444444-4444-4444-8444-444444444444"
	start := make(chan struct{})
	var admitted atomic.Int32
	var wg sync.WaitGroup
	errors := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, _, err := st.RateLimitTakeCost(ctx, tenant, "agent:first-use", 3, 0, 1)
			if err != nil {
				errors <- err
			} else if allowed {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent first-use take: %v", err)
	}
	if got := admitted.Load(); got != 3 {
		t.Fatalf("concurrent first-use bucket admitted %d, want 3", got)
	}
}
