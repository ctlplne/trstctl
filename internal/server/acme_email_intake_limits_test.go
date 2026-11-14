// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// P15-L8: each source of the reply intake holds at most its sessions at once
// and spends at most its replies a minute, refilled continuously; an IPv6
// source is its /64; the table of sources is bounded, dropping idle sources
// to make room and turning a new source away when none is idle.
func TestIntakeHoldsEachSourceToItsSessionsAndRepliesP15L8(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	limits := newACMEIntakeSources(2, 3)
	limits.now = func() time.Time { return now }
	a, b := net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")
	first, ok1 := limits.open(a)
	_, ok2 := limits.open(a)
	if _, ok3 := limits.open(a); !ok1 || !ok2 || ok3 {
		t.Fatalf("sessions from one source = %v %v %v; want two admitted", ok1, ok2, ok3)
	}
	if _, ok := limits.open(b); !ok {
		t.Fatal("another source was held to the first one's sessions")
	}
	first()
	if _, ok := limits.open(a); !ok {
		t.Fatal("a released session did not make room")
	}
	for i := 0; i < 3; i++ {
		if !limits.take(a) {
			t.Fatalf("reply %d of the budget was refused", i+1)
		}
	}
	if limits.take(a) {
		t.Fatal("a fourth reply within the minute was taken")
	}
	now = now.Add(20 * time.Second)
	if !limits.take(a) || limits.take(a) {
		t.Fatal("twenty seconds did not refill exactly one reply")
	}
	if intakeSourceKey(net.ParseIP("2001:db8:1:2::1")) != intakeSourceKey(net.ParseIP("2001:db8:1:2::ff")) ||
		intakeSourceKey(net.ParseIP("2001:db8:1:2::1")) == intakeSourceKey(net.ParseIP("2001:db8:1:3::1")) {
		t.Fatal("an IPv6 source is not its /64")
	}

	full := newACMEIntakeSources(1, 3)
	full.now = func() time.Time { return now }
	for i := 0; i < acmeIntakeMaxSources; i++ {
		if _, ok := full.open(net.ParseIP(fmt.Sprintf("10.%d.%d.1", i/256, i%256))); !ok {
			t.Fatalf("source %d was turned away below the bound", i)
		}
	}
	if _, ok := full.open(net.ParseIP("198.51.100.1")); ok {
		t.Fatal("a new source was admitted with the table full of busy sources")
	}
	idle := newACMEIntakeSources(1, 3)
	idle.now = func() time.Time { return now }
	for i := 0; i < acmeIntakeMaxSources; i++ {
		release, _ := idle.open(net.ParseIP(fmt.Sprintf("10.%d.%d.1", i/256, i%256)))
		release()
	}
	if _, ok := idle.open(net.ParseIP("198.51.100.1")); !ok {
		t.Fatal("idle sources were not dropped to make room")
	}
}
