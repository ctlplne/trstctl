// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
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
