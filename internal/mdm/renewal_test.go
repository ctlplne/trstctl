// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"strings"
	"testing"
	"time"
)

// The offline-renewal distinctions (I5). Each row exists because merging it
// with a neighbour sends an operator to the wrong laptop — or to no laptop,
// which is worse: the whole failure mode here is that NOTHING fails until the
// certificate already has.
func TestRenewalRiskDistinctions(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	at := func(s string) *time.Time {
		ts, err := time.Parse("2006-01-02", s)
		if err != nil {
			t.Fatal(err)
		}
		return &ts
	}
	cases := []struct {
		name     string
		notAfter *time.Time
		lastSeen *time.Time
		window   int
		atRisk   bool
		wants    string
	}{
		{"no certificate, no verdict", nil, at("2026-08-01"), 30, false, ""},
		{"expired is said as expired", at("2026-08-01"), at("2026-08-07"), 30, true, "EXPIRED"},
		{"outside the window, healthy", at("2026-12-01"), nil, 30, false, ""},
		{"inside window, never seen", at("2026-08-20"), nil, 30, true, "never observed"},
		{"inside window, seen before it opened", at("2026-08-20"), at("2026-06-01"), 30, true, "before"},
		{"inside window, checked in since it opened", at("2026-08-20"), at("2026-08-05"), 30, false, ""},
		{"zero window uses the standard", at("2026-08-20"), nil, 0, true, "never observed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			atRisk, detail := RenewalRisk(tc.notAfter, tc.lastSeen, tc.window, now)
			if atRisk != tc.atRisk {
				t.Fatalf("atRisk = %v, want %v (detail %q).\n\n"+
					"The false positive floods the list until operators ignore it; the false "+
					"negative is a certificate expiring in a drawer while every dashboard is green.",
					atRisk, tc.atRisk, detail)
			}
			if tc.wants != "" && !strings.Contains(detail, tc.wants) {
				t.Fatalf("detail %q does not carry %q; the words are what the operator acts on", detail, tc.wants)
			}
			if !tc.atRisk && detail != "" {
				t.Fatalf("a healthy device carries detail %q; noise on the healthy rows is how the "+
					"unhealthy ones get skimmed past", detail)
			}
		})
	}
}
