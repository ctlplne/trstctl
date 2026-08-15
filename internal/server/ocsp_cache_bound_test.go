// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strconv"
	"testing"
	"time"
)

// TestOCSPResponseCacheIsBounded is the regression guard for the unauthenticated
// memory-exhaustion defect. The cache key includes the requested serial and
// /ocsp is a public responder, so every distinct serial minted a permanent
// entry: eviction only ever happened when the SAME key was queried again after
// expiry, which a serial the attacker never repeats never is.
func TestOCSPResponseCacheIsBounded(t *testing.T) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()
	live := now.Add(time.Hour)

	// Far more distinct serials than the bound, as an unauthenticated client
	// would produce by walking serial numbers.
	for i := 0; i < maxOCSPCacheEntries*3; i++ {
		key := ocspResponseCacheKey{
			tenantID: "tenant-a", caID: "ca-1",
			serial: strconv.Itoa(i), status: "good", revokedAt: now,
		}
		c.put(key, []byte("response-der"), live, now)
	}

	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	if size > maxOCSPCacheEntries {
		t.Fatalf("cache holds %d entries after %d distinct serials, bound is %d; "+
			"an unauthenticated client can exhaust control-plane memory",
			size, maxOCSPCacheEntries*3, maxOCSPCacheEntries)
	}
}

// TestOCSPResponseCacheStillServesHits keeps the bound honest: a cached response
// must still be returned, so the fix cannot be "never cache anything".
func TestOCSPResponseCacheStillServesHits(t *testing.T) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()
	key := ocspResponseCacheKey{tenantID: "tenant-a", caID: "ca-1", serial: "42", status: "good", revokedAt: now}

	c.put(key, []byte("response-der"), now.Add(time.Hour), now)
	got, ok := c.get(key, now)
	if !ok || string(got) != "response-der" {
		t.Fatalf("cached response not served back: ok=%v got=%q", ok, got)
	}

	// And an expired entry is still not served.
	if _, ok := c.get(key, now.Add(2*time.Hour)); ok {
		t.Fatal("an expired OCSP response was served from cache")
	}
}

// TestOCSPResponseCacheEvictsExpiredBeforeLive proves the eviction order is not
// arbitrary: with the cache full of expired entries, a new put reclaims those
// rather than discarding a live response.
func TestOCSPResponseCacheEvictsExpiredBeforeLive(t *testing.T) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()

	for i := 0; i < maxOCSPCacheEntries; i++ {
		c.put(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "old-" + strconv.Itoa(i)},
			[]byte("stale"), now.Add(time.Minute), now)
	}
	later := now.Add(time.Hour)
	fresh := ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "fresh"}
	c.put(fresh, []byte("fresh-der"), later.Add(time.Hour), later)

	if got, ok := c.get(fresh, later); !ok || string(got) != "fresh-der" {
		t.Fatalf("a live response was evicted in favour of expired entries: ok=%v got=%q", ok, got)
	}
}
