package server

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

type ocspResponseCache struct {
	mu      sync.Mutex
	entries map[string]ocspResponseCacheEntry
}

type ocspResponseCacheEntry struct {
	der        []byte
	nextUpdate time.Time
}

type ocspResponseCacheKey struct {
	tenantID        string
	caID            string
	serial          string
	status          string
	reason          int
	revokedAt       time.Time
	responderSerial string
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
	c.entries[key.String()] = ocspResponseCacheEntry{der: append([]byte(nil), der...), nextUpdate: nextUpdate}
}

func (k ocspResponseCacheKey) String() string {
	parts := []string{
		k.tenantID,
		k.caID,
		k.serial,
		k.status,
		strconv.Itoa(k.reason),
		k.revokedAt.UTC().Format(time.RFC3339Nano),
		k.responderSerial,
	}
	return strings.Join(parts, "\x1f")
}
