// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"testing"
	"time"
)

// TestRateLimitRefillUsesTheDatabaseClock is the regression guard for the mixed
// clocks in the token bucket.
//
// updated_at is written with the DATABASE's now(), but the refill was computed
// with time.Since() on the APP's clock. Those are never guaranteed to agree, and
// each control-plane replica brings its own. Skew ahead of the database inflated
// the refill and let callers exceed their limit; skew behind it made the elapsed
// interval negative, so every take SUBTRACTED from the bucket and drove a tenant
// into a throttle that waiting could not clear.
//
// A unit test cannot move the host clock, so this pins the observable
// consequence: refill must track real elapsed time as the database measures it,
// and must never run backwards.
func TestRateLimitRefillUsesTheDatabaseClock(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const tenant = "33333333-3333-3333-3333-333333333333"

	// Drain a capacity-2 bucket that refills fast enough to observe.
	const capacity, refillPerSec = 2.0, 20.0
	for i := 0; i < 2; i++ {
		ok, _, err := st.RateLimitTake(ctx, tenant, "clock", capacity, refillPerSec)
		if err != nil {
			t.Fatalf("RateLimitTake: %v", err)
		}
		if !ok {
			t.Fatalf("take %d of a full capacity-2 bucket was shed", i+1)
		}
	}
	ok, retry, err := st.RateLimitTake(ctx, tenant, "clock", capacity, refillPerSec)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a third immediate take on a capacity-2 bucket was admitted")
	}
	if retry <= 0 || retry > time.Second {
		t.Errorf("retry-after = %v, want a small positive duration at %g tokens/sec", retry, refillPerSec)
	}

	// After real elapsed time the bucket must refill. At 20 tokens/sec, 150ms is
	// ~3 tokens — comfortably more than the 1 needed, so this does not race.
	time.Sleep(150 * time.Millisecond)
	ok, _, err = st.RateLimitTake(ctx, tenant, "clock", capacity, refillPerSec)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the bucket did not refill after real elapsed time; the refill interval is " +
			"being measured against a clock that disagrees with the one writing updated_at")
	}
}

// TestRateLimitNeverDrainsBelowAFreshBucket guards the direction that turns skew
// into a stuck throttle: repeated takes must never leave a bucket in a state
// where elapsed time makes things worse rather than better.
func TestRateLimitNeverDrainsBelowAFreshBucket(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const tenant = "44444444-4444-4444-4444-444444444444"
	const capacity, refillPerSec = 3.0, 1000.0

	// With a very fast refill, every take after a short pause must be admitted.
	// If elapsed time were ever computed as negative, tokens would ratchet down
	// and this would start shedding.
	for i := 0; i < 6; i++ {
		time.Sleep(10 * time.Millisecond)
		ok, retry, err := st.RateLimitTake(ctx, tenant, "drain", capacity, refillPerSec)
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("take %d was shed (retry %v) on a bucket refilling at %g tokens/sec; "+
				"elapsed time is being applied as a debit rather than a credit", i, retry, refillPerSec)
		}
	}
}
