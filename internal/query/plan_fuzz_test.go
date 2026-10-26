// SPDX-License-Identifier: BUSL-1.1

package query

import (
	"testing"
	"time"
)

// FuzzPlanQuestion: whatever the text, a plan's values stay bounded and
// typed, and a planned window is always inside 1 to 365 days.
func FuzzPlanQuestion(f *testing.F) {
	for _, seed := range []string{
		"Which certificates expire within 30 days?",
		`how many certificates are issued by "Acme" and have no owner`,
		"who owns 0011223344556677",
		"which crypto assets use RSA keys smaller than 2048 bits",
		"Which certificates expire within 999999999999999999999 days?",
		"\x00\nWhich certs expire within 1 day?",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, question string) {
		p, ok := PlanQuestion(question, time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
		if !ok {
			return
		}
		if p.ExpiryDays != 0 && (p.ExpiryDays < 1 || p.ExpiryDays > 365) {
			t.Fatalf("planned an out-of-range window %d for %q", p.ExpiryDays, question)
		}
		if f := p.Spec.Certificates; f != nil {
			for _, v := range []string{f.IssuerContains, f.NameContains, f.OwnerName, f.Serial, f.Fingerprint} {
				if len(v) > 200 {
					t.Fatalf("planned an unbounded value for %q", question)
				}
			}
		}
		if len(p.Spec.Select) == 0 || len(p.Spec.Focus) == 0 || p.Interpretation == "" {
			t.Fatalf("incomplete plan for %q: %+v", question, p)
		}
	})
}
