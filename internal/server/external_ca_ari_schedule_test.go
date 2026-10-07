// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestUpstreamARIRenewalOverridesLocalWindowAndRetainsExpirySafety(t *testing.T) {
	issued := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(90 * 24 * time.Hour)
	cert := store.Certificate{
		Fingerprint: strings.Repeat("a", 64), NotBefore: &issued, NotAfter: &expires,
		Source: "issued", IssuingExternalCAID: "pebble", CreatedAt: issued,
		IssuanceIdempotencyKey: "issue:transition:pebble",
	}
	cutoff := func(now time.Time) time.Time { return now.Add(30 * 24 * time.Hour) }
	beforeLocal := issued.Add(45 * 24 * time.Hour)
	earlyStart, earlyEnd := issued.Add(40*24*time.Hour), issued.Add(42*24*time.Hour)
	early := store.ACMEUpstreamARI{
		Status: "ready", AuthorityID: "pebble", WindowStart: &earlyStart, WindowEnd: &earlyEnd,
	}
	if _, due := lifecycleRenewalReason(cert, beforeLocal, cutoff(beforeLocal)); due {
		t.Fatal("local estimate unexpectedly open before authoritative early window")
	}
	if reason, due := upstreamARIRenewalReason(cert, early, beforeLocal, cutoff(beforeLocal)); !due ||
		!strings.HasPrefix(reason, lifecycleUpstreamARIRenewalReasonPrefix) {
		t.Fatalf("early upstream window was missed: due=%v reason=%q", due, reason)
	}
	lateStart, lateEnd := issued.Add(75*24*time.Hour), issued.Add(77*24*time.Hour)
	late := early
	late.WindowStart, late.WindowEnd = &lateStart, &lateEnd
	localOpen := issued.Add(65 * 24 * time.Hour)
	if _, due := lifecycleRenewalReason(cert, localOpen, cutoff(localOpen)); !due {
		t.Fatal("local estimate should be open in this fixture")
	}
	if reason, due := upstreamARIRenewalReason(cert, late, localOpen, cutoff(localOpen)); due {
		t.Fatalf("local estimate overrode later CA window: %q", reason)
	}
	queued := late
	queued.Status = "queued"
	queued.UpdatedAt = localOpen.Add(-time.Minute)
	if reason, due := upstreamARIRenewalReason(cert, queued, localOpen, cutoff(localOpen)); due {
		t.Fatalf("fresh queued first poll renewed before CA answered: %q", reason)
	}
	late.Status = "error" // retain last authoritative window during outage
	if reason, due := upstreamARIRenewalReason(cert, late, localOpen, cutoff(localOpen)); due {
		t.Fatalf("outage erased prior CA timing: %q", reason)
	}
	emergency := expires.Add(-12 * time.Hour)
	if reason, due := upstreamARIRenewalReason(cert, late, emergency, cutoff(emergency)); !due ||
		!strings.HasPrefix(reason, lifecycleUpstreamARIRenewalReasonPrefix) {
		t.Fatalf("CA window already passed at emergency: due=%v reason=%q", due, reason)
	}
	futureStart, futureEnd := expires.Add(time.Hour), expires.Add(2*time.Hour)
	impossible := late
	impossible.WindowStart, impossible.WindowEnd = &futureStart, &futureEnd
	if reason, due := upstreamARIRenewalReason(cert, impossible, emergency, cutoff(emergency)); !due ||
		!strings.HasPrefix(reason, lifecycleFixedRenewalReasonPrefix) {
		t.Fatalf("impossible CA hint suppressed expiry rescue: due=%v reason=%q", due, reason)
	}
	late.Status = "unavailable"
	if reason, due := upstreamARIRenewalReason(cert, late, localOpen, cutoff(localOpen)); !due ||
		!strings.HasPrefix(reason, lifecycleARIRenewalReasonPrefix) {
		t.Fatalf("no-advertisement did not restore local schedule: due=%v reason=%q", due, reason)
	}
}
