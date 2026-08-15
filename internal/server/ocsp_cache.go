// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strconv"
	"strings"
	"sync"
	"time"
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

func (c *ocspResponseCache) put(key ocspResponseCacheKey, der []byte, nextUpdate time.Time) {
	if c == nil || len(der) == 0 || nextUpdate.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replacing := c.entries[key.String()]; !replacing {
		c.evictLocked(nextUpdate)
	}
	c.entries[key.String()] = ocspResponseCacheEntry{der: append([]byte(nil), der...), nextUpdate: nextUpdate}
}

// evictLocked makes room for one new entry. It first drops everything already
// expired — the common case, and free — and only if the cache is still full
// evicts the entry that expires soonest, which is the one whose loss costs the
// least. Callers hold c.mu.
func (c *ocspResponseCache) evictLocked(now time.Time) {
	if len(c.entries) < maxOCSPCacheEntries {
		return
	}
	for k, entry := range c.entries {
		if !entry.nextUpdate.After(now) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= maxOCSPCacheEntries {
		var soonestKey string
		var soonest time.Time
		for k, entry := range c.entries {
			if soonestKey == "" || entry.nextUpdate.Before(soonest) {
				soonestKey, soonest = k, entry.nextUpdate
			}
		}
		if soonestKey == "" {
			return
		}
		delete(c.entries, soonestKey)
	}
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
