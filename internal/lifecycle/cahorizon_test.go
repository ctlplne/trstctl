// SPDX-License-Identifier: BUSL-1.1

package lifecycle

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/notify"
)

var horizonNow = time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)

func months(n int) time.Duration { return time.Duration(float64(n)) * approxMonth }

// TestCAHorizonBandPicksTheTightestCrossedThreshold is the core of the calendar:
// an authority sits in exactly one band, the tightest one it has crossed, so an
// alert says how much runway is left rather than which thresholds are behind it.
func TestCAHorizonBandPicksTheTightestCrossedThreshold(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		want     int
		wantOK   bool
	}{
		{"five years out is not news yet", horizonNow.Add(months(60)), 0, false},
		{"just past the widest threshold", horizonNow.Add(months(37)), 0, false},
		{"thirty months lands in the 36-month band", horizonNow.Add(months(30)), 36, true},
		{"eighteen months lands in the 24-month band", horizonNow.Add(months(18)), 24, true},
		{"ten months lands in the 12-month band", horizonNow.Add(months(10)), 12, true},
		{"five months lands in the 6-month band", horizonNow.Add(months(5)), 6, true},
		{"two months lands in the 3-month band", horizonNow.Add(months(2)), 3, true},
		{"one week lands in the tightest band", horizonNow.Add(7 * 24 * time.Hour), 3, true},
		{"already expired is band zero and still reportable", horizonNow.Add(-time.Hour), 0, true},
		{"unknown expiry is not a horizon", time.Time{}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CAHorizonBand(horizonNow, tc.notAfter)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("CAHorizonBand = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestCAHorizonBandIsTheGapLeafAlertingLeaves is the reason the epic exists: the
// leaf scheduler's widest window is 90 days, and a root at 30 months needs a
// warning today. This pins that the calendar fires where leaf alerting is silent.
func TestCAHorizonBandIsTheGapLeafAlertingLeaves(t *testing.T) {
	root := horizonNow.Add(months(30))

	// The leaf-scale threshold used by AlertExpiring would report nothing useful:
	// its severity floor is "low" for anything beyond 30 days and it has no band
	// at all beyond the configured alert window.
	if days := expiryThresholdDays(horizonNow, root); days <= 90 {
		t.Fatalf("fixture is wrong: a 30-month root should be far outside leaf windows, got %d days", days)
	}
	band, ok := CAHorizonBand(horizonNow, root)
	if !ok {
		t.Fatal("a root 30 months out must raise a horizon band; that is the whole point of the CA calendar")
	}
	if band != 36 {
		t.Fatalf("band = %d, want 36", band)
	}
	if got := CAHorizonSeverity(band); got != notify.AlertSeverityLow {
		t.Fatalf("severity at 36 months = %q, want %q — a three-year horizon is a planning signal, not an alarm",
			got, notify.AlertSeverityLow)
	}
}

// TestCAHorizonSeverityScalesToRunway pins the judgment encoded in the bands:
// under three months there is no time left to distribute a new anchor.
func TestCAHorizonSeverityScalesToRunway(t *testing.T) {
	cases := map[int]string{
		36: notify.AlertSeverityLow,
		24: notify.AlertSeverityLow,
		12: notify.AlertSeverityWarning,
		6:  notify.AlertSeverityWarning,
		3:  notify.AlertSeverityCritical,
		0:  notify.AlertSeverityCritical,
	}
	for band, want := range cases {
		if got := CAHorizonSeverity(band); got != want {
			t.Errorf("CAHorizonSeverity(%d) = %q, want %q", band, got, want)
		}
	}
}

// TestMonthsRemainingRoundsDownSoBandsDoNotFlicker keeps an authority inside a
// band for the whole of that band. Rounding up would push it into the next band a
// day early and re-alert on a boundary nobody crossed.
func TestMonthsRemainingRoundsDownSoBandsDoNotFlicker(t *testing.T) {
	if got := MonthsRemaining(horizonNow, horizonNow.Add(months(12)+20*24*time.Hour)); got != 12 {
		t.Errorf("MonthsRemaining just past 12 months = %d, want 12", got)
	}
	if got := MonthsRemaining(horizonNow, horizonNow.Add(-time.Hour)); got != 0 {
		t.Errorf("MonthsRemaining for an expired authority = %d, want 0", got)
	}
	if got := MonthsRemaining(horizonNow, time.Time{}); got != 0 {
		t.Errorf("MonthsRemaining with no expiry = %d, want 0", got)
	}
}

// TestCompressedValidityCatchesTheSilentTruncation is the second half of the
// epic. A CA cannot issue a leaf that outlives it, so once its remaining life
// drops below the leaf validity, every renewal quietly produces a shorter
// certificate and nothing errors.
func TestCompressedValidityCatchesTheSilentTruncation(t *testing.T) {
	const leaf = 90 * 24 * time.Hour

	t.Run("healthy parent issues full-length leaves", func(t *testing.T) {
		compressed, actual := CompressedValidity(horizonNow, horizonNow.Add(months(24)), leaf)
		if compressed {
			t.Error("a parent 24 months out is not compressing a 90-day leaf")
		}
		if actual != leaf {
			t.Errorf("actual validity = %v, want the full %v", actual, leaf)
		}
	})

	t.Run("parent inside the leaf window truncates silently", func(t *testing.T) {
		compressed, actual := CompressedValidity(horizonNow, horizonNow.Add(30*24*time.Hour), leaf)
		if !compressed {
			t.Fatal("a parent 30 days out cannot issue a 90-day leaf; that must be flagged")
		}
		if actual != 30*24*time.Hour {
			t.Errorf("actual validity = %v, want 30 days — the leaf is truncated to the parent's expiry", actual)
		}
	})

	t.Run("expired parent yields zero validity", func(t *testing.T) {
		compressed, actual := CompressedValidity(horizonNow, horizonNow.Add(-time.Hour), leaf)
		if !compressed || actual != 0 {
			t.Errorf("expired parent = (%v, %v), want (true, 0)", compressed, actual)
		}
	})

	t.Run("no opinion on leaf validity means no compression claim", func(t *testing.T) {
		if compressed, _ := CompressedValidity(horizonNow, horizonNow.Add(time.Hour), 0); compressed {
			t.Error("with no reference leaf validity there is nothing to compare against, so nothing to claim")
		}
	})
}

// TestCARenewByIsWhenTruncationStarts ties the console's "renew/re-key by" date
// to the compression check: they are the same boundary seen from two sides.
func TestCARenewByIsWhenTruncationStarts(t *testing.T) {
	const leaf = 90 * 24 * time.Hour
	notAfter := horizonNow.Add(months(12))
	renewBy := CARenewBy(notAfter, leaf)

	if !renewBy.Equal(notAfter.Add(-leaf)) {
		t.Fatalf("CARenewBy = %v, want %v", renewBy, notAfter.Add(-leaf))
	}
	if compressed, _ := CompressedValidity(renewBy.Add(-time.Hour), notAfter, leaf); compressed {
		t.Error("an hour before renew-by, leaves still get their full validity")
	}
	if compressed, _ := CompressedValidity(renewBy.Add(time.Hour), notAfter, leaf); !compressed {
		t.Error("an hour after renew-by, leaves are being truncated — that is what the date means")
	}
	if got := CARenewBy(time.Time{}, leaf); !got.IsZero() {
		t.Error("an authority with no expiry has no renew-by date")
	}
	if got := CARenewBy(notAfter, 0); !got.Equal(notAfter) {
		t.Error("with no leaf-validity opinion, renew-by collapses to the expiry itself")
	}
}
