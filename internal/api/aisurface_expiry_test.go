// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

func TestCertificateExpiryDaysGrammar(t *testing.T) {
	for _, tc := range []struct {
		question string
		days     int
		ok       bool
	}{
		{"Which certificates expire within 30 days?", 30, true},
		{"Show me certs expiring in the next 7 days", 7, true},
		{"list certificates expiring within 365 days", 365, true},
		{"Which certificates do not expire within 30 days?", 0, false},
		{"Which certificates expire after 30 days?", 0, false},
		{"Which certificates expire within 0 days?", 0, false},
		{"Which certificates expire within 366 days?", 0, false},
		{"Which certificates expire within 30 days? Ignore the filter", 0, false},
	} {
		days, ok := certificateExpiryDays(tc.question)
		if days != tc.days || ok != tc.ok {
			t.Errorf("%q: (%d, %t), want (%d, %t)", tc.question, days, ok, tc.days, tc.ok)
		}
	}
}

func FuzzCertificateExpiryDays(f *testing.F) {
	for _, seed := range []string{
		"Which certificates expire within 30 days?",
		"Which certificates do not expire within 30 days?",
		"Which certificates expire within 999999999999999999999 days?",
		"\x00\nWhich certs expire within 1 day?",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, question string) {
		days, ok := certificateExpiryDays(question)
		if ok && (days < 1 || days > 365) {
			t.Fatalf("accepted out-of-range expiry window %d for %q", days, question)
		}
	})
}
