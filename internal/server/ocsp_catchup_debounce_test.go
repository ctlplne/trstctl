// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"
	"time"
)

// TestOCSPCatchUpIsRateLimited is the regression guard for the unauthenticated
// replay-amplification defect. /ocsp is public, and activeOCSPResponder ran a
// FULL projection catch-up on every cache miss — and the requested serial is
// part of the cache key, so a client that simply varied the serial drove one
// whole-event-log replay per request, each under the global projection lock,
// starving every other projection consumer.
//
// The tail worker is what keeps the read model current; this catch-up is a
// freshness backstop, and a backstop must not run at a rate the caller chooses.
func TestOCSPCatchUpIsRateLimited(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	// A service with no log/store: catchUp short-circuits before touching them,
	// so this exercises the rate limiter itself.
	s := &revocationService{now: func() time.Time { return now }}

	// First call is allowed and stamps the clock.
	if err := s.catchUp(t.Context()); err != nil {
		t.Fatalf("first catch-up: %v", err)
	}
	first := s.lastCatchUp
	if first.IsZero() {
		t.Fatal("catch-up did not record when it last ran; the rate limit cannot work")
	}

	// A burst inside the interval must not re-stamp — i.e. must not have run.
	for i := 0; i < 1000; i++ {
		if err := s.catchUp(t.Context()); err != nil {
			t.Fatalf("burst catch-up %d: %v", i, err)
		}
	}
	if !s.lastCatchUp.Equal(first) {
		t.Fatal("a burst of unauthenticated requests each triggered a full projection replay")
	}

	// Past the interval, the backstop runs again — staleness is still bounded.
	now = now.Add(ocspCatchUpInterval + time.Second)
	if err := s.catchUp(t.Context()); err != nil {
		t.Fatalf("catch-up after the interval: %v", err)
	}
	if s.lastCatchUp.Equal(first) {
		t.Fatal("catch-up never ran again; the read model would go stale indefinitely")
	}
}
