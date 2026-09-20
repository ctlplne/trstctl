// SPDX-License-Identifier: BUSL-1.1

package secretsdk

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeFetcher struct {
	mu      sync.Mutex
	calls   int
	value   []byte
	ttl     time.Duration
	now     func() time.Time
	failNow bool // simulate a revoked credential
}

func (f *fakeFetcher) Fetch(_ context.Context, _ string) ([]byte, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNow {
		return nil, time.Time{}, errors.New("credential revoked")
	}
	return f.value, f.now().Add(f.ttl), nil
}

func TestSDKCachesAndRefreshes(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := &fakeFetcher{value: []byte("v"), ttl: time.Hour, now: clock}
	c := New(f, WithClock(clock), WithRefreshFraction(0.5))
	ctx := context.Background()

	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "p"); err != nil { // within fresh window → cached
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Errorf("fetch called %d times within fresh window, want 1 (cache)", f.calls)
	}
	// Advance past the refresh threshold (>50% of a 1h lifetime).
	now = now.Add(40 * time.Minute)
	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Errorf("fetch called %d times after refresh threshold, want 2", f.calls)
	}
}

func TestSDKFailsSafeOnRevokedRefresh(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := &fakeFetcher{value: []byte("v"), ttl: time.Hour, now: clock}
	c := New(f, WithClock(clock), WithRefreshFraction(0.5))
	ctx := context.Background()
	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	// Credential revoked; advance past refresh so the next Get refreshes.
	f.failNow = true
	now = now.Add(40 * time.Minute)
	if _, err := c.Get(ctx, "p"); err == nil {
		t.Error("Get returned a value despite a revoked credential on refresh (not fail-safe)")
	}
}

// capturingFetcher returns a fresh copy of value on each Fetch and keeps a handle
// to the slice it most recently handed the cache, so a test can inspect whether
// that backing array was zeroized after eviction (GAP-007).
type capturingFetcher struct {
	value    []byte
	ttl      time.Duration
	now      func() time.Time
	lastSent []byte
}

func (f *capturingFetcher) Fetch(_ context.Context, _ string) ([]byte, time.Time, error) {
	cp := append([]byte(nil), f.value...)
	f.lastSent = cp
	return cp, f.now().Add(f.ttl), nil
}

// TestSDKEvictZeroizesCachedSecret is the GAP-007 acceptance: Evict (and Close)
// must zeroize the cached secret's backing array, not merely drop the map entry, so
// secret bytes do not linger in freed heap (AN-8). Pre-fix Evict/Close did not
// exist and the cache only delete()d, leaving the bytes un-wiped; this fails then.
func TestSDKEvictZeroizesCachedSecret(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := &capturingFetcher{value: []byte("super-secret-value"), ttl: time.Hour, now: clock}
	c := New(f, WithClock(clock))
	ctx := context.Background()

	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	// The cache holds its own copy; capture it via the entry, then evict and assert
	// the cache's backing array is all-zero.
	cachedBacking := c.cache["p"].value
	if allZero(cachedBacking) {
		t.Fatal("cached secret was already zero before eviction (test setup wrong)")
	}
	c.Evict("p")
	if _, ok := c.cache["p"]; ok {
		t.Error("Evict did not remove the cache entry")
	}
	if !allZero(cachedBacking) {
		t.Errorf("Evict did not zeroize the cached secret backing array: %v", cachedBacking)
	}

	// Close zeroizes the whole cache.
	if _, err := c.Get(ctx, "p2"); err != nil {
		t.Fatal(err)
	}
	backing2 := c.cache["p2"].value
	c.Close()
	if len(c.cache) != 0 {
		t.Error("Close did not clear the cache")
	}
	if !allZero(backing2) {
		t.Errorf("Close did not zeroize cached secret: %v", backing2)
	}
}

// TestSDKReplaceZeroizesPriorValue is the GAP-007 acceptance for the replace path:
// refreshing a cached secret zeroizes the prior cached value before overwriting it.
func TestSDKReplaceZeroizesPriorValue(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := &capturingFetcher{value: []byte("v1-secret"), ttl: time.Hour, now: clock}
	c := New(f, WithClock(clock), WithRefreshFraction(0.5))
	ctx := context.Background()
	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	prior := c.cache["p"].value
	// Advance past refresh and change the upstream value so the entry is replaced.
	now = now.Add(40 * time.Minute)
	f.value = []byte("v2-secret")
	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if !allZero(prior) {
		t.Errorf("prior cached value not zeroized on replace: %v", prior)
	}
}

// TestSDKTenantAttribution is the GAP-009 acceptance: a Client is tenant-scoped and
// exposes its tenant, so a server-side caller mints one Client per tenant and the
// (per-Client) cache is per-tenant by construction.
func TestSDKTenantAttribution(t *testing.T) {
	f := &fakeFetcher{value: []byte("v"), ttl: time.Hour, now: time.Now}
	c := New(f, WithTenant("tenant-A"))
	if c.TenantID() != "tenant-A" {
		t.Errorf("TenantID = %q, want tenant-A", c.TenantID())
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}
