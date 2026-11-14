// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"testing"
	"time"
)

// M4-L6: each client holds perMinute requests and refills at that rate; one
// client's use never spends another's; the table stays bounded: when it is
// full of clients still refilling, new clients share one overflow bucket, and
// once buckets have refilled they are swept to make room.
func TestClientRateLimiterBoundsEachClientM4L6(t *testing.T) {
	start := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	l := newClientRateLimiter(3, 2)
	for i := range 3 {
		if _, ok := l.allow("198.51.100.7", start); !ok {
			t.Fatalf("request %d of 3 refused", i+1)
		}
	}
	wait, ok := l.allow("198.51.100.7", start)
	if ok || wait < 19*time.Second || wait > 21*time.Second {
		t.Fatalf("the fourth request = %v %v; want refused with about 20s to the next token", wait, ok)
	}
	if _, ok := l.allow("198.51.100.8", start); !ok {
		t.Fatal("another client was refused by the first client's use")
	}
	// The table is full of two clients still refilling: new clients share the
	// overflow bucket's three tokens, and the table does not grow.
	for i := range 3 {
		if _, ok := l.allow(fmt.Sprintf("203.0.113.%d", i), start); !ok {
			t.Fatalf("overflow request %d refused", i+1)
		}
	}
	if _, ok := l.allow("203.0.113.9", start); ok || l.size() != 2 {
		t.Fatalf("a request past the overflow's tokens was allowed, or the table grew to %d", l.size())
	}
	if _, ok := l.allow("198.51.100.7", start.Add(21*time.Second)); !ok {
		t.Fatal("a refilled token was refused")
	}
	// Two minutes on every bucket has refilled: they are swept for new clients.
	later := start.Add(2 * time.Minute)
	for i := range 2 {
		if _, ok := l.allow(fmt.Sprintf("192.0.2.%d", i), later); !ok {
			t.Fatalf("new client %d after the sweep refused", i)
		}
	}
	if l.size() != 2 {
		t.Fatalf("table = %d entries; want it bounded at 2", l.size())
	}
}
