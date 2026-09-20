// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestLifecycleRenewalReasonNamesTheCertificateExpiry(t *testing.T) {
	// Actual mail journey: the one-minute sweep ran 58 seconds after the
	// five-minute renewal window opened. Its cutoff is not the leaf's expiry.
	nb := time.Date(2026, 9, 13, 2, 21, 21, 0, time.UTC)
	na := time.Date(2026, 9, 13, 2, 33, 21, 0, time.UTC)
	anchor := nb.Add(5 * time.Minute)
	now := time.Date(2026, 9, 13, 2, 29, 19, 0, time.UTC)
	cert := store.Certificate{NotBefore: &nb, NotAfter: &na, ValidityAnchor: &anchor}
	reason, due := lifecycleRenewalReason(cert, now, now.Add(5*time.Minute))
	if !due || reason != "scheduled renewal before 2026-09-13T02:33:21Z" {
		t.Fatalf("renewal reason must retain actual leaf expiry, not the moving sweep cutoff: due=%v reason=%q", due, reason)
	}
}

// The live owned journey minted nine unnecessary successors: its 30-day
// fallback window was already open when each 30-day leaf was first recorded.
// These source regressions preserve the configured lead and certificate life.
func TestLifecycleRenewalWindowDoesNotRequeueFreshLeaves(t *testing.T) {
	issued := time.Date(2026, 9, 10, 13, 0, 40, 0, time.UTC)
	for _, lifetime := range []time.Duration{6 * time.Hour, 30 * 24 * time.Hour} {
		t.Run(lifetime.String(), func(t *testing.T) {
			for _, elapsed := range []time.Duration{time.Second, time.Minute, time.Hour} {
				nb, na := issued.Add(-5*time.Minute), issued.Add(lifetime)
				cert := store.Certificate{NotBefore: &nb, NotAfter: &na, ValidityAnchor: &issued, CreatedAt: issued.Add(time.Second)}
				now := issued.Add(elapsed)
				if reason, due := lifecycleRenewalReason(cert, now, now.Add(30*24*time.Hour)); due {
					t.Errorf("fresh lifetime=%s age=%s was scheduled again: %s", lifetime, elapsed, reason)
				}
			}
		})
	}
}

func TestLifecycleRenewalWindowPreservesRealDeadlinesAndARI(t *testing.T) {
	issued := time.Date(2026, 9, 10, 13, 0, 40, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		life, age  time.Duration
		lead       time.Duration
		due        bool
		wantPrefix string
	}{
		{"fresh 47-day leaf", 47 * 24 * time.Hour, time.Minute, 30 * 24 * time.Hour, false, ""},
		{"47-day leaf before configured deadline", 47 * 24 * time.Hour, 16 * 24 * time.Hour, 30 * 24 * time.Hour, false, ""},
		{"47-day leaf reaches configured deadline before ARI", 47 * 24 * time.Hour, 17*24*time.Hour + time.Second, 30 * 24 * time.Hour, true, lifecycleFixedRenewalReasonPrefix},
		{"short leaf reaches existing ARI window", 30 * 24 * time.Hour, 20 * 24 * time.Hour, 30 * 24 * time.Hour, true, lifecycleARIRenewalReasonPrefix},
		{"ARI precedes narrow fallback", 90 * 24 * time.Hour, 61 * 24 * time.Hour, time.Hour, true, lifecycleARIRenewalReasonPrefix},
		{"expired leaf remains due", 6 * time.Hour, 7 * time.Hour, 30 * 24 * time.Hour, true, lifecycleARIRenewalReasonPrefix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nb, na := issued.Add(-5*time.Minute), issued.Add(tc.life)
			cert := store.Certificate{NotBefore: &nb, NotAfter: &na, ValidityAnchor: &issued, CreatedAt: issued.Add(time.Second)}
			now := issued.Add(tc.age)
			reason, due := lifecycleRenewalReason(cert, now, now.Add(tc.lead))
			if due != tc.due || (tc.due && !strings.HasPrefix(reason, tc.wantPrefix)) {
				t.Fatalf("renewal = %t %q, want %t prefix %q", due, reason, tc.due, tc.wantPrefix)
			}
		})
	}
	// A late first observation must not move a genuine earlier deadline.
	nb47, na47 := issued.Add(-5*time.Minute), issued.Add(47*24*time.Hour)
	for _, anchor := range []*time.Time{nil, &issued} {
		delayed := store.Certificate{NotBefore: &nb47, NotAfter: &na47, ValidityAnchor: anchor, CreatedAt: issued.Add(20 * 24 * time.Hour)}
		now := delayed.CreatedAt
		if reason, due := lifecycleRenewalReason(delayed, now, now.Add(30*24*time.Hour)); !due || !strings.HasPrefix(reason, lifecycleFixedRenewalReasonPrefix) {
			t.Fatalf("late 47-day observation lost its day-17 deadline: %t %q", due, reason)
		}
	}
	na := issued.Add(time.Hour)
	if _, due := lifecycleRenewalReason(store.Certificate{NotAfter: &na}, issued, issued.Add(2*time.Hour)); !due {
		t.Fatal("missing legacy validity start must retain its fixed fallback")
	}
	if _, due := lifecycleRenewalReason(store.Certificate{}, issued, issued.Add(30*24*time.Hour)); due {
		t.Fatal("missing expiry cannot establish a renewal deadline")
	}
}
