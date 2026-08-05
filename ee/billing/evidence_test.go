// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"strings"
	"testing"
	"time"
)

var (
	pStart = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	pEnd   = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	after  = pEnd.Add(time.Hour)
)

func period() EvidencePeriod { return EvidencePeriod{CustomerID: "bank-a", Start: pStart, End: pEnd} }
func fullDurable() Coverage {
	return Coverage{ObservedFrom: pStart, ObservedTo: pEnd, Durable: true}
}

// The defect this epic exists to fix: in-memory metering loses usage SILENTLY.
// A signature over that figure is worse than no evidence.
func TestInMemoryUsageIsNeverSignedAsEvidence(t *testing.T) {
	t.Parallel()
	c := fullDurable()
	c.Durable = false
	got := MaySign(period(), c, after)
	if got.Signable {
		t.Fatal("in-memory usage was signed as invoice evidence.\n\n" +
			"It cannot be vouched for across a restart, and a provider cannot tell from the " +
			"figure alone whether one happened. The signature converts a gap somebody might have " +
			"questioned into a number they will rely on.")
	}
	if !strings.Contains(got.Reason, "silently short") {
		t.Errorf("the refusal does not explain the risk: %q", got.Reason)
	}
}

// A store whose own window does not span the period is short by an unknown
// amount.
func TestPartialCoverageCannotBeSigned(t *testing.T) {
	t.Parallel()
	c := fullDurable()
	c.ObservedFrom = pStart.Add(48 * time.Hour)
	if MaySign(period(), c, after).Signable {
		t.Fatal("a period was signed although the metering store only covers part of it. The " +
			"figure is short by an unknown amount, and the signature says otherwise")
	}
	c = fullDurable()
	c.ObservedTo = pEnd.Add(-time.Hour)
	if MaySign(period(), c, after).Signable {
		t.Fatal("a period was signed although metering stopped before it ended")
	}
}

// An open period is still accruing; signing it produces a partial month that
// reads like a final figure.
func TestAnOpenPeriodCannotBeSigned(t *testing.T) {
	t.Parallel()
	got := MaySign(period(), fullDurable(), pEnd.Add(-time.Hour))
	if got.Signable {
		t.Fatal("a period that had not closed was signed. Usage is still accruing, so the " +
			"evidence is for a partial month while reading like a final one")
	}
	if !strings.Contains(got.Reason, "still accruing") {
		t.Errorf("reason = %q", got.Reason)
	}
}

// The healthy path must actually work, or the rule is just a refusal.
func TestAClosedDurableFullyCoveredPeriodIsSignable(t *testing.T) {
	t.Parallel()
	got := MaySign(period(), fullDurable(), after)
	if !got.Signable {
		t.Fatalf("a closed, durable, fully covered period was refused: %q", got.Reason)
	}
}

// A refusal must say what is missing: "cannot sign" alone gets escalated as a
// bug instead of acted on as a gap.
func TestEveryRefusalExplainsWhatIsMissing(t *testing.T) {
	t.Parallel()
	nonDurable := fullDurable()
	nonDurable.Durable = false
	short := fullDurable()
	short.ObservedTo = pEnd.Add(-time.Hour)
	for _, tc := range []struct {
		name string
		got  EvidenceDecision
	}{
		{"non-durable", MaySign(period(), nonDurable, after)},
		{"short coverage", MaySign(period(), short, after)},
		{"open period", MaySign(period(), fullDurable(), pEnd.Add(-time.Hour))},
		{"no period", MaySign(EvidencePeriod{}, fullDurable(), after)},
	} {
		if tc.got.Signable {
			t.Fatalf("%s was signable", tc.name)
		}
		if len(strings.TrimSpace(tc.got.Reason)) < 20 {
			t.Errorf("%s refusal is too terse to act on: %q", tc.name, tc.got.Reason)
		}
	}
}
