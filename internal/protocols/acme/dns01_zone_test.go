// SPDX-License-Identifier: BUSL-1.1

package acme

import "testing"

// DNS01ZoneCovers is the one matching rule shared by order-time automation and
// the endpoint-lifecycle preview; pinning it keeps the two from drifting.
func TestDNS01ZoneCovers(t *testing.T) {
	cases := []struct {
		zone, challengeDomain, domain string
		want                          bool
	}{
		{"partner-lab.example.com", "", "apache.partner-lab.example.com", true},
		{"partner-lab.example.com.", "", "APACHE.partner-lab.example.com", true},
		{"partner-lab.example.com", "", "partner-lab.example.com", true},
		{"partner-lab.example.com", "", "*.partner-lab.example.com", true},
		{"partner-lab.example.com", "", "apache.example.com", false},
		{"lab.example.com", "", "apache.partner-lab.example.com", false},
		{"", "_acme-challenge.apache.partner-lab.example.com", "apache.partner-lab.example.com", true},
		{"", "acme.partner-lab.example.com", "web.acme.partner-lab.example.com", true},
		{"", "", "apache.partner-lab.example.com", false},
		{"partner-lab.example.com", "", "", false},
	}
	for _, tc := range cases {
		if got := DNS01ZoneCovers(tc.zone, tc.challengeDomain, tc.domain); got != tc.want {
			t.Errorf("DNS01ZoneCovers(%q, %q, %q) = %v, want %v", tc.zone, tc.challengeDomain, tc.domain, got, tc.want)
		}
	}
}

func TestDNS01ZoneMatchSpecificity(t *testing.T) {
	const domain = "delegated.partner-lab.example.com"
	parent := DNS01ZoneMatchSpecificity("partner-lab.example.com", "", domain)
	child := DNS01ZoneMatchSpecificity("delegated.partner-lab.example.com", "validation.partner-lab.example.com", domain)
	record := DNS01ZoneMatchSpecificity("", "_acme-challenge.delegated.partner-lab.example.com", domain)
	if parent <= 0 || child <= parent || record <= child {
		t.Fatalf("specificity parent=%d child=%d exact challenge=%d; want increasing scope", parent, child, record)
	}
	if got := DNS01ZoneMatchSpecificity("other.example.com", "", domain); got != 0 {
		t.Fatalf("unrelated zone specificity = %d, want zero", got)
	}
	if got := DNS01ZoneMatchSpecificity("delegated.partner-lab.example.com.", "", "*.DELEGATED.partner-lab.example.com."); got != child {
		t.Fatalf("wildcard/case/trailing-dot specificity = %d, want %d", got, child)
	}
}
