// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"sync"
	"time"
)

// defaultJTICacheCap bounds the jti replay cache when no explicit cap is given.
// The cache holds one small entry (a jti string + an expiry) per recently-seen
// token; it self-evicts expired entries, so this cap only matters under a flood
// of distinct, still-valid tokens (AN-7: bounded, no unbounded growth).
const defaultJTICacheCap = 65536

// JTICache is a bounded, expiring set of JWT IDs (jti) used to reject replayed
// tokens. It is safe for concurrent use. Entries are dropped once their token's
// exp has passed (a replay is only meaningful while the token is still otherwise
// valid), so the cache never needs to remember a jti longer than the token lives.
type JTICache struct {
	mu  sync.Mutex
	cap int
	m   map[string]time.Time // jti -> token expiry
}

// NewJTICache returns a replay cache bounded to maxEntries (<=0 selects
// defaultJTICacheCap).
func NewJTICache(maxEntries int) *JTICache {
	if maxEntries <= 0 {
		maxEntries = defaultJTICacheCap
	}
	return &JTICache{cap: maxEntries, m: make(map[string]time.Time)}
}

// Add records jti as seen until exp, evaluated against now. It returns true if
// the jti was newly recorded (first use) and false if it was already present and
// still valid (a replay). Expired entries are reclaimed lazily; if the cache is
// at capacity a sweep of expired entries is attempted before accepting a new one,
// and a still-full cache fails closed (rejects) so it can never grow unbounded.
func (c *JTICache) Add(jti string, exp, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.m[jti]; ok {
		if now.Before(prev) {
			return false // replay: same jti, token still within its validity
		}
		// The previous sighting's token has expired; this is a distinct token (or
		// a clock has advanced past the old exp). Treat as a fresh first use.
		c.m[jti] = exp
		return true
	}
	if len(c.m) >= c.cap {
		c.sweep(now)
		if len(c.m) >= c.cap {
			return false // bounded: refuse rather than exceed the cap (AN-7)
		}
	}
	c.m[jti] = exp
	return true
}

// sweep removes entries whose expiry is at or before now. Caller holds the lock.
func (c *JTICache) sweep(now time.Time) {
	for jti, exp := range c.m {
		if !now.Before(exp) {
			delete(c.m, jti)
		}
	}
}

// Len reports the number of cached entries (for tests/inspection).
func (c *JTICache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
