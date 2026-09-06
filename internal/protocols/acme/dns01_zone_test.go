// SPDX-License-Identifier: MPL-2.0

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
