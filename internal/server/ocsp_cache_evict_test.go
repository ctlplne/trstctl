// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strconv"
	"testing"
	"time"
)

// TestOCSPCacheAtCapEvictsExactlyOneLiveEntry is the regression guard for
// AUD-201 follow-up F1/V7. put passed the NEW entry's nextUpdate (now + TTL)
// into evictLocked as "now", so the expiry sweep judged every existing live
// entry against a future timestamp: under the production reality of one
// uniform TTL, every entry qualified and one new serial mass-deleted ~8191
// still-valid responses. /ocsp is unauthenticated and mints one entry per
// distinct serial, so at the cap every request from a serial-walking client
// flushed the whole cache, collapsed the hit rate, and forced a fresh
// SignDelegatedOCSPResponseWithNonce per legitimate query — reinstating the
// signer-load amplification the bound was added to absorb. The earlier bound
// test missed it because size <= max is satisfied by a mass flush.
func TestOCSPCacheAtCapEvictsExactlyOneLiveEntry(t *testing.T) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()
	uniformExpiry := now.Add(time.Hour)

	for i := 0; i < maxOCSPCacheEntries; i++ {
		c.put(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "live-" + strconv.Itoa(i)},
			[]byte("live-der"), uniformExpiry, now)
	}
	// The insert that used to trigger the flush: same wall clock, an expiry at
	// or beyond every existing one (uniform TTL, marginally later "now").
	c.put(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "newcomer"},
		[]byte("new-der"), now.Add(90*time.Minute), now)

	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	if size != maxOCSPCacheEntries {
		t.Fatalf("cache size after an at-cap insert = %d, want %d (exactly one eviction); "+
			"a smaller size means live entries were mass-flushed", size, maxOCSPCacheEntries)
	}

	survivors := 0
	for i := 0; i < maxOCSPCacheEntries; i++ {
		key := ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "live-" + strconv.Itoa(i)}
		if _, ok := c.get(key, now); ok {
			survivors++
		}
	}
	if survivors != maxOCSPCacheEntries-1 {
		t.Fatalf("%d of %d live entries survived the at-cap insert, want all but one",
			survivors, maxOCSPCacheEntries)
	}
	if _, ok := c.get(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "newcomer"}, now); !ok {
		t.Fatal("the newly inserted entry is not served")
	}
}

// TestOCSPCacheEvictsTheSoonestExpiringEntry proves the evict-soonest branch is
// reachable and picks the right victim — it was dead code under the old
// future-clock sweep, contradicting its own comment.
func TestOCSPCacheEvictsTheSoonestExpiringEntry(t *testing.T) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()

	for i := 0; i < maxOCSPCacheEntries; i++ {
		// Staggered live expiries: serial "live-0" expires soonest.
		c.put(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "live-" + strconv.Itoa(i)},
			[]byte("live-der"), now.Add(time.Hour+time.Duration(i)*time.Second), now)
	}
	c.put(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "newcomer"},
		[]byte("new-der"), now.Add(2*time.Hour), now)

	if _, ok := c.get(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "live-0"}, now); ok {
		t.Fatal("the soonest-expiring live entry survived; the eviction did not pick the cheapest victim")
	}
	if _, ok := c.get(ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "live-1"}, now); !ok {
		t.Fatal("a longer-lived entry was evicted instead of the soonest-expiring one")
	}
	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	if size != maxOCSPCacheEntries {
		t.Fatalf("cache size = %d, want %d", size, maxOCSPCacheEntries)
	}
}
