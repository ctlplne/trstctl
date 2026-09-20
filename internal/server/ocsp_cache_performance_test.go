// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// A public responder must retain the most useful live responses when a caller
// walks many serials. Refreshing an existing key can move its expiry in either
// direction, so eviction must use its current expiry rather than its old one.
func TestOCSPCacheRefreshChangesTheEvictionOrder(t *testing.T) {
	for _, earlier := range []bool{false, true} {
		t.Run(strconv.FormatBool(earlier), func(t *testing.T) {
			c := newOCSPResponseCache()
			now := time.Unix(1_900_000_000, 0).UTC()
			key := func(i int) ocspResponseCacheKey {
				return ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: strconv.Itoa(i)}
			}
			for i := range maxOCSPCacheEntries {
				c.put(key(i), []byte("original"), now.Add(time.Hour+time.Duration(i)*time.Second), now)
			}
			refreshed, victim := 0, 1
			expires := now.Add(3 * time.Hour)
			if earlier {
				refreshed, victim = maxOCSPCacheEntries-1, maxOCSPCacheEntries-1
				expires = now.Add(time.Minute)
			}
			c.put(key(refreshed), []byte("replacement"), expires, now)
			c.put(key(maxOCSPCacheEntries), []byte("new"), now.Add(4*time.Hour), now)
			for i := range maxOCSPCacheEntries + 1 {
				got, ok := c.get(key(i), now)
				if i == victim {
					if ok {
						t.Fatalf("soonest expiry %d survived eviction", i)
					}
					continue
				}
				want := "original"
				if i == refreshed {
					want = "replacement"
				}
				if i == maxOCSPCacheEntries {
					want = "new"
				}
				if !ok || string(got) != want {
					t.Fatalf("serial %d: hit=%t result=%q want=%q", i, ok, got, want)
				}
			}
		})
	}
}

func TestOCSPCacheConcurrentReadsAndExpiryKeepResponsesIndependent(t *testing.T) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Go(func() {
			for i := range 512 {
				key := ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: strconv.Itoa(worker*512 + i)}
				input := []byte("certificate-status")
				c.put(key, input, now.Add(time.Minute), now)
				input[0] = 'x'
				got, ok := c.get(key, now)
				if !ok || string(got) != "certificate-status" {
					t.Errorf("cached response shares caller bytes: hit=%t got=%q", ok, got)
					return
				}
				got[0] = 'y'
				fresh, ok := c.get(key, now)
				if !ok || string(fresh) != "certificate-status" {
					t.Error("a reader changed another reader's response")
					return
				}
				if _, ok := c.get(key, now.Add(time.Minute)); ok {
					t.Error("response remained usable at its expiry")
					return
				}
			}
		})
	}
	workers.Wait()
}

// The same bounded, full cache is used for both implementations. No network,
// signer, synthetic wait, or reduced capacity contributes to this measurement.
func BenchmarkOCSPCacheFullSerialChurn(b *testing.B) {
	c := newOCSPResponseCache()
	now := time.Unix(1_900_000_000, 0).UTC()
	key := func(i int) ocspResponseCacheKey {
		return ocspResponseCacheKey{tenantID: "t", caID: "ca", serial: strconv.Itoa(i)}
	}
	for i := range maxOCSPCacheEntries {
		c.put(key(i), []byte("response-der"), now.Add(time.Hour), now)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		c.put(key(maxOCSPCacheEntries+i), []byte("response-der"), now.Add(time.Hour), now)
	}
}
