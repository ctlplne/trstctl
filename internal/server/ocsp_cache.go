// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ttlmap"
)

// maxOCSPCacheEntries bounds the served OCSP response cache.
//
// The cache key includes the requested SERIAL, and /ocsp is an unauthenticated
// public responder, so without a bound any client could mint a new cache entry
// per request and grow control-plane memory without limit — entries were only
// ever evicted when the SAME key was queried again after expiry, which a serial
// the attacker never repeats never is. 8192 entries is far above any real
// working set (a responder answers for a bounded population of live
// certificates) and small enough that the worst case is megabytes, not the heap.
const maxOCSPCacheEntries = 8192

type ocspResponseCache struct {
	mu      sync.Mutex
	entries map[string]ocspResponseCacheEntry
}

type ocspResponseCacheEntry struct {
	der        []byte
	nextUpdate time.Time
}

type ocspResponseCacheKey struct {
	tenantID  string
	caID      string
	serial    string
	status    string
	reason    int
	revokedAt time.Time
}

func newOCSPResponseCache() *ocspResponseCache {
	return &ocspResponseCache{entries: make(map[string]ocspResponseCacheEntry)}
}

func (c *ocspResponseCache) get(key ocspResponseCacheKey, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key.String()]
	if !ok {
		return nil, false
	}
	if !entry.nextUpdate.After(now) {
		delete(c.entries, key.String())
		return nil, false
	}
	return append([]byte(nil), entry.der...), true
}

func (c *ocspResponseCache) put(key ocspResponseCacheKey, der []byte, nextUpdate, now time.Time) {
	if c == nil || len(der) == 0 || nextUpdate.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replacing := c.entries[key.String()]; !replacing {
		// Evict against the caller's REAL clock. This used to pass the new
		// entry's nextUpdate (now + TTL) as "now", so the expiry sweep judged
		// every live entry against a future timestamp: at the cap, one new
		// serial mass-deleted every still-valid response and the hit rate
		// collapsed — reinstating exactly the signer-load amplification the
		// bound was added to absorb (AUD-201 follow-up F1/V7).
		c.evictLocked(now)
	}
	c.entries[key.String()] = ocspResponseCacheEntry{der: append([]byte(nil), der...), nextUpdate: nextUpdate}
}

// evictLocked makes room for one new entry via the shared bounded-TTL-map
// algorithm (F2/V28): expired entries first — the common case, and free —
// then the entry that expires soonest, whose loss costs the least. Callers
// hold c.mu.
func (c *ocspResponseCache) evictLocked(now time.Time) {
	ttlmap.MakeRoom(c.entries, now, ttlmap.Policy[ocspResponseCacheEntry]{
		Capacity: maxOCSPCacheEntries,
		Expired: func(e ocspResponseCacheEntry, now time.Time) bool {
			return !e.nextUpdate.After(now)
		},
		Rank: func(e ocspResponseCacheEntry) time.Time { return e.nextUpdate },
	})
}

func (k ocspResponseCacheKey) String() string {
	parts := []string{
		k.tenantID,
		k.caID,
		k.serial,
		k.status,
		strconv.Itoa(k.reason),
		k.revokedAt.UTC().Format(time.RFC3339Nano),
	}
	return strings.Join(parts, "\x1f")
}
