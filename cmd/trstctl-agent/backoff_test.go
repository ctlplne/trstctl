package main

import (
	"math/rand"
	"testing"
	"time"
)

// TestRotateBackoffIsBoundedJitteredAndPositive is the RESIL-006 acceptance for the
// agent's rotation retry schedule: on a control-plane outage the daemon retries a
// failed rotation with full-jitter exponential backoff instead of waiting a full
// rotate-every interval. The schedule must (a) always be strictly positive (so a
// recovering agent never spins in a tight loop), (b) never exceed the cap (so a
// long outage does not back off to absurd delays), and (c) be jittered (two
// independent RNG streams produce different delays at the same attempt, so a fleet
// de-correlates and does not stampede the control plane).
//
// It runs with seeded RNGs so it is fully deterministic (no time.Now, no flake).
func TestRotateBackoffIsBoundedJitteredAndPositive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	// (a) + (b): every attempt yields a positive delay no greater than the cap, and
	// the *ceiling* grows monotonically up to the cap.
	for attempt := 0; attempt < 20; attempt++ {
		d := rotateBackoff(attempt, rng)
		if d <= 0 {
			t.Fatalf("rotateBackoff(%d) = %v, want strictly positive (no spin)", attempt, d)
		}
		if d > rotateBackoffMax {
			t.Fatalf("rotateBackoff(%d) = %v, want <= cap %v", attempt, d, rotateBackoffMax)
		}
	}

	// The uncapped exponential ceiling for a given attempt is base*2^attempt (capped
	// at Max). Full jitter draws in (0, ceiling], so a large sample's max should
	// approach the ceiling at a small attempt and never exceed it.
	ceilingAt := func(attempt int) time.Duration {
		d := rotateBackoffBase
		for i := 0; i < attempt && d < rotateBackoffMax; i++ {
			d *= 2
		}
		if d > rotateBackoffMax {
			d = rotateBackoffMax
		}
		return d
	}
	r := rand.New(rand.NewSource(42))
	var maxSeen time.Duration
	const attempt = 3 // ceiling = 8s
	for i := 0; i < 5000; i++ {
		d := rotateBackoff(attempt, r)
		if d > ceilingAt(attempt) {
			t.Fatalf("rotateBackoff(%d) = %v exceeded its ceiling %v", attempt, d, ceilingAt(attempt))
		}
		if d > maxSeen {
			maxSeen = d
		}
	}
	// With 5000 draws in (0, 8s] the observed max should be close to the ceiling.
	if maxSeen < ceilingAt(attempt)/2 {
		t.Fatalf("max jittered delay over 5000 draws = %v, want closer to the ceiling %v (jitter range too narrow)", maxSeen, ceilingAt(attempt))
	}

	// (c) jitter: two independent streams differ at the same attempt (not a fixed
	// schedule). Compare a handful of draws; at least one must differ.
	a := rand.New(rand.NewSource(7))
	b := rand.New(rand.NewSource(9))
	differs := false
	for i := 0; i < 8; i++ {
		if rotateBackoff(5, a) != rotateBackoff(5, b) {
			differs = true
			break
		}
	}
	if !differs {
		t.Fatal("two independent RNG streams produced identical backoff delays; jitter is not applied (fleet would stampede)")
	}
}

// TestRotateBackoffCapsAtMax confirms the exponential growth saturates at the cap:
// a high attempt index must have its ceiling clamped, so the jittered draw stays
// within (0, Max].
func TestRotateBackoffCapsAtMax(t *testing.T) {
	r := rand.New(rand.NewSource(123))
	for i := 0; i < 1000; i++ {
		if d := rotateBackoff(50, r); d <= 0 || d > rotateBackoffMax {
			t.Fatalf("rotateBackoff(50) = %v, want in (0, %v]", d, rotateBackoffMax)
		}
	}
}

func TestHeartbeatDelayUsesServerHintWithBoundedJitter(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	const hintSeconds = int64(30)
	min := 24 * time.Second
	max := 30 * time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 100; i++ {
		d := heartbeatDelaySeconds(hintSeconds, defaultHeartbeatInterval, rng)
		if d < min || d > max {
			t.Fatalf("heartbeatDelaySeconds(%d) = %v, want in [%v, %v]", hintSeconds, d, min, max)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Fatal("heartbeat delay did not jitter; a fleet would re-synchronize on the server hint")
	}
}

func TestHeartbeatDelayFallsBackAndNeverSpins(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	fallback := 10 * time.Second
	for _, seconds := range []int64{-5, 0} {
		d := heartbeatDelaySeconds(seconds, fallback, rng)
		if d < 8*time.Second || d > fallback {
			t.Fatalf("heartbeatDelaySeconds(%d) = %v, want bounded fallback jitter", seconds, d)
		}
	}
	if d := heartbeatDelaySeconds(1, 0, rng); d <= 0 || d > time.Second {
		t.Fatalf("heartbeatDelaySeconds with no fallback = %v, want positive delay no greater than hint", d)
	}
}
