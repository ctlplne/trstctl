// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"time"
)

// B13-R2: the responder reused a cached response until its nextUpdate, so a
// relying party could be handed a ten-minute response with seconds left (and a
// relay's health probe read the managed CA as "expiring"). A cached response is
// reused only in the first half of its life; then a new one is signed and
// replaces it in place.
func TestOCSPCacheRefreshesAtHalfLife(t *testing.T) {
	c := newOCSPResponseCache()
	key := ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: "01", status: "good"}
	now := time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC)
	c.put(key, []byte("first"), now.Add(10*time.Minute), now)
	if got, ok := c.get(key, now.Add(4*time.Minute+59*time.Second)); !ok || string(got) != "first" {
		t.Fatalf("get before half-life = %q, %t; want the cached response", got, ok)
	}
	if got, ok := c.get(key, now.Add(5*time.Minute)); ok {
		t.Fatalf("get at half-life returned %q; want a miss so a new response is signed", got)
	}
	later := now.Add(5 * time.Minute)
	c.put(key, []byte("second"), later.Add(10*time.Minute), later)
	if got, ok := c.get(key, later.Add(4*time.Minute)); !ok || string(got) != "second" {
		t.Fatalf("get after the refresh = %q, %t; want the new response", got, ok)
	}
	if len(c.entries) != 1 || len(c.expiry) != 1 {
		t.Fatalf("refresh left %d entries / %d heap nodes, want one of each", len(c.entries), len(c.expiry))
	}
}
