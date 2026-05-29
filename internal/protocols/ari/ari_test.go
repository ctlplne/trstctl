package ari

import (
	"testing"
	"time"
)

// TestSuggestWindowWithinValidity: a normal renewal window falls before expiry,
// after issuance, and start precedes end.
func TestSuggestWindowWithinValidity(t *testing.T) {
	notBefore := time.Now().Add(-30 * 24 * time.Hour)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	w := SuggestWindow(notBefore, notAfter, time.Now(), false)
	if !w.Start.Before(w.End) {
		t.Errorf("window start %v not before end %v", w.Start, w.End)
	}
	if w.Start.Before(notBefore) || w.End.After(notAfter) {
		t.Errorf("window [%v,%v] outside validity [%v,%v]", w.Start, w.End, notBefore, notAfter)
	}
}

// TestEarlyRenewalWindowSignalsNow: an early-renewal window (mass-revocation
// signal) starts at or before now, so the client renews proactively.
func TestEarlyRenewalWindowSignalsNow(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-10 * 24 * time.Hour)
	notAfter := now.Add(80 * 24 * time.Hour)
	w := SuggestWindow(notBefore, notAfter, now, true)
	if w.Start.After(now) {
		t.Errorf("early-renewal window start %v is after now %v; should signal renew-now", w.Start, now)
	}
	if !RenewNow(RenewalInfo{SuggestedWindow: w}, now) {
		t.Error("RenewNow should be true for an early-renewal window")
	}
}

// TestRenewNowRespectsWindow: a future window is window-driven, not timer-driven —
// the client does not renew merely because "now" arrived; it renews once now
// reaches the window start.
func TestRenewNowRespectsWindow(t *testing.T) {
	now := time.Now()
	w := Window{Start: now.Add(10 * 24 * time.Hour), End: now.Add(11 * 24 * time.Hour)}
	info := RenewalInfo{SuggestedWindow: w}
	if RenewNow(info, now) {
		t.Error("RenewNow should be false before the window start (renew within window, not on a timer)")
	}
	if !RenewNow(info, w.Start) {
		t.Error("RenewNow should be true once now reaches the window start")
	}
}

// TestRenewAtWithinWindow: the scheduled renewal time lies within the advertised
// window and is deterministic for a given seed.
func TestRenewAtWithinWindow(t *testing.T) {
	now := time.Now()
	w := Window{Start: now.Add(20 * 24 * time.Hour), End: now.Add(25 * 24 * time.Hour)}
	info := RenewalInfo{SuggestedWindow: w}
	at := RenewAt(info, 42)
	if at.Before(w.Start) || at.After(w.End) {
		t.Errorf("RenewAt %v outside window [%v,%v]", at, w.Start, w.End)
	}
	if !RenewAt(info, 42).Equal(at) {
		t.Error("RenewAt is not deterministic for a fixed seed")
	}
}

// TestParseCertIDRoundTrip: a well-formed certificate identifier decodes to its
// AKI and serial bytes.
func TestParseCertIDRoundTrip(t *testing.T) {
	akid, serial, err := ParseCertID("aGVsbG8.d29ybGQ") // base64url("hello").base64url("world")
	if err != nil {
		t.Fatalf("ParseCertID: %v", err)
	}
	if string(akid) != "hello" || string(serial) != "world" {
		t.Errorf("decoded akid=%q serial=%q, want hello/world", akid, serial)
	}
}

// TestValidCertID accepts a well-formed id and rejects malformed ones.
func TestValidCertID(t *testing.T) {
	if !ValidCertID("aGVsbG8.d29ybGQ") {
		t.Error("a well-formed cert id was rejected")
	}
	for _, bad := range []string{"", "nodot", "a.b.c", ".only", "only.", "!!!.@@@"} {
		if ValidCertID(bad) {
			t.Errorf("malformed cert id %q was accepted", bad)
		}
	}
}

// FuzzParseCertID: the parser never panics on arbitrary input.
func FuzzParseCertID(f *testing.F) {
	f.Add("aGVsbG8.d29ybGQ")
	f.Add("")
	f.Add("nodot")
	f.Add("a.b.c")
	f.Add("!!!.@@@")
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = ParseCertID(s)
	})
}
