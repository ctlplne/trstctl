// SPDX-License-Identifier: BUSL-1.1

package revcache

import (
	"fmt"
	"testing"
	"time"
)

func TestOCSPResponseCacheEvictsExpiredThenOldestWithinBoundAUD39(t *testing.T) {
	now := time.Now().UTC()
	cache := &managedOCSP{now: func() time.Time { return now }, responses: map[string]ocspCachedResponse{}}
	cache.responses["expired"] = ocspCachedResponse{nextUpdate: now.Add(-time.Second), validatedAt: now.Add(time.Hour)}
	for i := 0; i < maxOCSPCacheResponses; i++ {
		cache.responses[fmt.Sprintf("valid-%04d", i)] = ocspCachedResponse{
			nextUpdate: now.Add(time.Hour), validatedAt: now.Add(time.Duration(i) * time.Second),
		}
	}

	cache.makeCacheRoomLocked()
	if len(cache.responses) != maxOCSPCacheResponses-1 {
		t.Fatalf("cache entries after reserving one slot = %d, want %d", len(cache.responses), maxOCSPCacheResponses-1)
	}
	if _, ok := cache.responses["expired"]; ok {
		t.Fatal("expired response survived bounded-cache cleanup")
	}
	if _, ok := cache.responses["valid-0000"]; ok {
		t.Fatal("oldest valid response survived after the cache still needed one eviction")
	}
}
