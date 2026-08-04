// SPDX-License-Identifier: MPL-2.0

package lifecycle_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/lifecycle"
)

// Maintenance windows decide when a renewal may touch production (epic D6).
//
// The failure modes here are quiet ones: a window that excludes the hours it
// was meant to include, or a default that stops every renewal in a deployment
// nobody configured. Both look like the scheduler working correctly right up
// until a certificate expires.

// An unconfigured deployment must renew normally.
//
// This is the one that would have been a fleet-wide outage: an operator who has
// configured no windows has not asked for a freeze, and defaulting to closed
// would turn a new feature into an expiry event across every install that
// upgraded.
func TestAnEmptyWindowSetAllowsEverything(t *testing.T) {
	t.Parallel()
	var none lifecycle.WindowSet
	for _, at := range []time.Time{
		time.Date(2026, 8, 4, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 4, 14, 30, 0, 0, time.UTC),
		time.Date(2026, 8, 9, 23, 59, 0, 0, time.UTC),
	} {
		if !none.Allows(at) {
			t.Fatalf("an unconfigured deployment refused a renewal at %s; nobody asked for a freeze", at)
		}
	}
	if none.DeferralReason(time.Now()) != "" {
		t.Error("an unconfigured deployment produced a deferral reason")
	}
}

// The overnight window is the one most operators actually want, and it wraps
// midnight. Treating 22:00–06:00 as a configuration error — or as an empty
// range — would exclude precisely the hours it was written to include.
func TestAnOvernightWindowWrapsMidnight(t *testing.T) {
	t.Parallel()
	w, err := lifecycle.ParseWindow("22:00-06:00")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set := lifecycle.WindowSet{w}

	inside := []time.Time{
		time.Date(2026, 8, 4, 22, 30, 0, 0, time.UTC),
		time.Date(2026, 8, 4, 23, 59, 0, 0, time.UTC),
		time.Date(2026, 8, 5, 0, 1, 0, 0, time.UTC),
		time.Date(2026, 8, 5, 5, 59, 0, 0, time.UTC),
	}
	for _, at := range inside {
		if !set.Allows(at) {
			t.Errorf("%s should be inside a 22:00-06:00 window", at.Format(time.RFC3339))
		}
	}
	outside := []time.Time{
		time.Date(2026, 8, 5, 6, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 5, 21, 59, 0, 0, time.UTC),
	}
	for _, at := range outside {
		if set.Allows(at) {
			t.Errorf("%s should be outside a 22:00-06:00 window", at.Format(time.RFC3339))
		}
	}
}

// "Friday night" means Friday 22:00 through Saturday 06:00. Checking only the
// current weekday would slam the window shut at midnight and leave the second
// half of every overnight window unusable — the half most changes run in.
func TestAWrappingWindowNamedOnADayCoversTheFollowingMorning(t *testing.T) {
	t.Parallel()
	w, err := lifecycle.ParseWindow("Fri 22:00-06:00")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set := lifecycle.WindowSet{w}

	friday2300 := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC) // a Friday
	if friday2300.Weekday() != time.Friday {
		t.Fatalf("fixture is not a Friday: %s", friday2300.Weekday())
	}
	if !set.Allows(friday2300) {
		t.Error("Friday 23:00 is outside a Friday-night window")
	}
	saturday0300 := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	if !set.Allows(saturday0300) {
		t.Error("Saturday 03:00 is outside a window that opened on Friday night; the hours " +
			"belong to the day the window opened on, which is what 'Friday night' means")
	}
	saturday2300 := time.Date(2026, 8, 8, 23, 0, 0, 0, time.UTC)
	if set.Allows(saturday2300) {
		t.Error("Saturday 23:00 is inside a Friday-only window")
	}
}

// A deferral names WHEN, not just that it happened. "Not now" is not actionable;
// "not until Saturday 22:00" tells an operator whether to wait or intervene.
func TestADeferralNamesTheNextOpening(t *testing.T) {
	t.Parallel()
	w, err := lifecycle.ParseWindow("Sat,Sun 00:00-23:59")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set := lifecycle.WindowSet{w}

	wednesday := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	if set.Allows(wednesday) {
		t.Fatal("a weekend-only window admitted a Wednesday")
	}
	reason := set.DeferralReason(wednesday)
	if reason == "" {
		t.Fatal("a deferred renewal produced no reason")
	}
	if !strings.Contains(reason, "Sat") {
		t.Errorf("reason = %q; it must name when the window next opens, or an operator cannot "+
			"tell whether to wait or to intervene", reason)
	}
	next := set.NextOpen(wednesday)
	if next.Weekday() != time.Saturday {
		t.Errorf("NextOpen = %s, want the coming Saturday", next.Weekday())
	}
}

// Timezones are named, not offsets, so a window follows daylight saving the way
// the person who wrote it expects. A fixed offset would drift an hour twice a
// year, in the small hours, where nobody would notice until something renewed
// during a freeze.
func TestWindowsHonourNamedTimezones(t *testing.T) {
	t.Parallel()
	w, err := lifecycle.ParseWindow("22:00-23:00 America/New_York")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set := lifecycle.WindowSet{w}

	// 22:30 in New York during daylight saving is 02:30 UTC the next day.
	inWindow := time.Date(2026, 7, 15, 2, 30, 0, 0, time.UTC)
	if !set.Allows(inWindow) {
		t.Errorf("%s UTC is 22:30 in New York and should be inside the window",
			inWindow.Format(time.RFC3339))
	}
	// The same UTC hour in January is 21:30 New York — outside.
	outOfWindow := time.Date(2026, 1, 15, 2, 30, 0, 0, time.UTC)
	if set.Allows(outOfWindow) {
		t.Errorf("%s UTC is 21:30 in New York and should be outside; a fixed offset would have "+
			"got this wrong by an hour", outOfWindow.Format(time.RFC3339))
	}
}

// The spec form is what a change-advisory board reads. Malformed input is
// refused rather than silently interpreted as something else.
func TestWindowSpecParsing(t *testing.T) {
	t.Parallel()
	ok := []string{
		"22:00-06:00",
		"Sat,Sun 00:00-23:59",
		"Mon,Tue,Wed,Thu,Fri 20:00-04:00 UTC",
		"Fri 22:00-06:00 Europe/London",
	}
	for _, spec := range ok {
		if _, err := lifecycle.ParseWindow(spec); err != nil {
			t.Errorf("ParseWindow(%q) failed: %v", spec, err)
		}
	}
	bad := []string{"", "notaday 10:00-11:00", "Mon", "10:00", "Mon 25:00-26:00", "Mon 10:00-10:99"}
	for _, spec := range bad {
		if _, err := lifecycle.ParseWindow(spec); err == nil {
			t.Errorf("ParseWindow(%q) accepted malformed input", spec)
		}
	}
}
