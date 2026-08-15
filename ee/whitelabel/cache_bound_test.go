// SPDX-License-Identifier: LicenseRef-trstctl-EE

package whitelabel

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestBrandCacheIsBounded is the regression guard for the unauthenticated
// memory-exhaustion and query-amplification defect. The cache key comes from the
// request's Host header, so an unauthenticated client chooses it; the map grew
// without bound, and every miss fell through to a database fetch.
func TestBrandCacheIsBounded(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	r := &Resolver{cache: map[string]cachedRecord{}, ttl: time.Minute, now: func() time.Time { return now }}

	var fetches atomic.Int64
	fetch := func(context.Context) (*Record, error) {
		fetches.Add(1)
		return nil, nil // not found — the answer for an unknown host
	}

	for i := 0; i < maxBrandCacheEntries*3; i++ {
		r.lookup(context.Background(), "host-"+strconv.Itoa(i)+".example", fetch)
	}

	r.mu.Lock()
	size := len(r.cache)
	r.mu.Unlock()
	if size > maxBrandCacheEntries {
		t.Fatalf("cache holds %d entries after %d distinct hosts, bound is %d",
			size, maxBrandCacheEntries*3, maxBrandCacheEntries)
	}
}

// TestBrandCacheCachesNegativeAnswers pins the amplification half: a repeated
// unknown Host must be answered from cache, not re-queried every request.
func TestBrandCacheCachesNegativeAnswers(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	r := &Resolver{cache: map[string]cachedRecord{}, ttl: time.Minute, now: func() time.Time { return now }}

	var fetches atomic.Int64
	fetch := func(context.Context) (*Record, error) {
		fetches.Add(1)
		return nil, nil
	}

	for i := 0; i < 50; i++ {
		r.lookup(context.Background(), "unknown.example", fetch)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("an unknown Host caused %d database lookups over 50 requests, want 1; "+
			"each request amplifies into a query", got)
	}
}

// TestBrandCacheDoesNotCacheTransientErrors keeps the negative caching honest: a
// transient failure must not be remembered, or one blip becomes a TTL-long
// outage for a legitimate tenant.
func TestBrandCacheDoesNotCacheTransientErrors(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	r := &Resolver{cache: map[string]cachedRecord{}, ttl: time.Minute, now: func() time.Time { return now }}

	var fetches atomic.Int64
	fetch := func(context.Context) (*Record, error) {
		fetches.Add(1)
		return nil, context.DeadlineExceeded
	}
	r.lookup(context.Background(), "flaky.example", fetch)
	r.lookup(context.Background(), "flaky.example", fetch)
	if got := fetches.Load(); got != 2 {
		t.Fatalf("a transient error was cached (%d lookups, want 2); a blip would become a TTL-long outage", got)
	}
}
