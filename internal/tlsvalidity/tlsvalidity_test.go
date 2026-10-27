// SPDX-License-Identifier: BUSL-1.1

package tlsvalidity_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/tlsvalidity"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// A178: the table of BR 2.3.1 section 6.3.2, by issuance instant.
func TestStepForFollowsTheDatedTable(t *testing.T) {
	for _, tc := range []struct {
		issued          string
		should, maxDays int
	}{
		{"2025-12-31T23:59:59Z", 397, 398},
		{"2026-03-14T23:59:59Z", 397, 398},
		{"2026-03-15T00:00:00Z", 199, 200},
		{"2027-03-14T23:59:59Z", 199, 200},
		{"2027-03-15T00:00:00Z", 99, 100},
		{"2029-03-14T23:59:59Z", 99, 100},
		{"2029-03-15T00:00:00Z", 46, 47},
		{"2040-01-01T00:00:00Z", 46, 47},
	} {
		step := tlsvalidity.StepFor(at(tc.issued))
		if step.ShouldDays != tc.should || step.MaxDays != tc.maxDays {
			t.Errorf("issued %s → %d/%d, want %d/%d", tc.issued, step.ShouldDays, step.MaxDays, tc.should, tc.maxDays)
		}
	}
	if got := len(tlsvalidity.Reductions()); got != 3 {
		t.Fatalf("reductions = %d, want the 2026, 2027 and 2029 steps", got)
	}
	if !tlsvalidity.StepFor(at("2026-10-26T00:00:00Z")).InEffect(at("2026-10-26T00:00:00Z")) {
		t.Fatal("the step a certificate is issued under is in effect at issuance")
	}
}

// The Validity Period includes the notAfter second, and any part of a day is a
// day: exactly 200 days apart is one second too long for a 200-day maximum.
func TestValidityDaysCountsTheBRWay(t *testing.T) {
	nb := at("2026-04-01T00:00:00Z")
	day := 24 * time.Hour
	for _, tc := range []struct {
		lifetime time.Duration
		days     int
	}{
		{0, 1},
		{day - time.Second, 1},
		{day, 2},
		{200*day - time.Second, 200},
		{200 * day, 201},
		{397 * day, 398},
		{398*day - time.Second, 398},
		{47*day - time.Second, 47},
	} {
		if got := tlsvalidity.ValidityDays(nb, nb.Add(tc.lifetime)); got != tc.days {
			t.Errorf("lifetime %s → %d days, want %d", tc.lifetime, got, tc.days)
		}
		if got := tlsvalidity.RequestedDays(tc.lifetime); got != tc.days {
			t.Errorf("requested %s → %d days, want %d", tc.lifetime, got, tc.days)
		}
	}
	if tlsvalidity.ValidityDays(nb, nb.Add(-time.Hour)) != 0 {
		t.Fatal("an inverted validity counted days")
	}
	step := tlsvalidity.StepFor(nb)
	if tlsvalidity.RequestedDays(step.MaxLifetime()) != step.MaxDays || tlsvalidity.RequestedDays(step.MaxLifetime()+time.Second) != step.MaxDays+1 {
		t.Fatalf("MaxLifetime %s is not the longest lifetime within %d days", step.MaxLifetime(), step.MaxDays)
	}
}
