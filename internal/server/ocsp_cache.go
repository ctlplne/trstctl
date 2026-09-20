// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"container/heap"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxOCSPCacheEntries bounds the public responder's cache. Distinct serials
// must not grow memory without limit or force a full-cache scan per request.
const maxOCSPCacheEntries = 8192

type ocspResponseCache struct {
	mu      sync.Mutex
	entries map[string]*ocspResponseCacheEntry
	expiry  ocspExpiryHeap
}

type ocspResponseCacheEntry struct {
	key        string
	der        []byte
	nextUpdate time.Time
	index      int
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
	return &ocspResponseCache{entries: make(map[string]*ocspResponseCacheEntry)}
}

func (c *ocspResponseCache) get(key ocspResponseCacheKey, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	id := key.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	if !ok {
		return nil, false
	}
	if !entry.nextUpdate.After(now) {
		c.removeLocked(entry)
		return nil, false
	}
	return append([]byte(nil), entry.der...), true
}

func (c *ocspResponseCache) put(key ocspResponseCacheKey, der []byte, nextUpdate, now time.Time) {
	if c == nil || len(der) == 0 || nextUpdate.IsZero() {
		return
	}
	id := key.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, replacing := c.entries[id]; replacing {
		entry.der = append([]byte(nil), der...)
		entry.nextUpdate = nextUpdate
		heap.Fix(&c.expiry, entry.index)
		return
	}
	c.evictLocked(now)
	entry := &ocspResponseCacheEntry{key: id, der: append([]byte(nil), der...), nextUpdate: nextUpdate}
	c.entries[id] = entry
	heap.Push(&c.expiry, entry)
}

// Preserve the bounded TTL policy: at capacity, remove expired entries first,
// then the soonest-expiring live entry, breaking ties by key. The indexed heap
// finds that entry in logarithmic time and keeps one node per cached response;
// refreshes cannot accumulate stale queue nodes. now is the caller's wall clock,
// never the new response's nextUpdate.
func (c *ocspResponseCache) evictLocked(now time.Time) {
	if len(c.entries) < maxOCSPCacheEntries {
		return
	}
	for len(c.expiry) > 0 && !c.expiry[0].nextUpdate.After(now) {
		c.removeLocked(c.expiry[0])
	}
	for len(c.entries) >= maxOCSPCacheEntries {
		c.removeLocked(c.expiry[0])
	}
}

func (c *ocspResponseCache) removeLocked(entry *ocspResponseCacheEntry) {
	heap.Remove(&c.expiry, entry.index)
	delete(c.entries, entry.key)
}

type ocspExpiryHeap []*ocspResponseCacheEntry

func (h ocspExpiryHeap) Len() int { return len(h) }
func (h ocspExpiryHeap) Less(i, j int) bool {
	if h[i].nextUpdate.Equal(h[j].nextUpdate) {
		return h[i].key < h[j].key
	}
	return h[i].nextUpdate.Before(h[j].nextUpdate)
}
func (h ocspExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *ocspExpiryHeap) Push(value any) {
	entry := value.(*ocspResponseCacheEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}
func (h *ocspExpiryHeap) Pop() any {
	last := len(*h) - 1
	entry := (*h)[last]
	(*h)[last] = nil
	*h = (*h)[:last]
	entry.index = -1
	return entry
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
