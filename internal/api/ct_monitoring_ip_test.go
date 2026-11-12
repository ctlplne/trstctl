// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"slices"
	"testing"
)

// TestCTWatchedEntriesAcceptIPAddressesAndRangesN10L2: CT monitoring may watch
// IP addresses and CIDR ranges beside domains (N10-L2), normalized (a range
// to its network, an address as itself); a range matching every address, a
// URL and a wildcard are refused.
func TestCTWatchedEntriesAcceptIPAddressesAndRangesN10L2(t *testing.T) {
	got, err := cleanCTWatchedDomains([]string{"Example.com.", "203.0.113.77/24", "198.51.100.7", "2001:DB8::/32", "198.51.100.7/32", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7", "2001:db8::/32", "203.0.113.0/24", "example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("watched = %q; want %q", got, want)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "https://example.com", "*.example.com", "10.0.0.0/33"} {
		if _, err := cleanCTWatchedDomains([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestCTPlanPreviewNamesIPWatchesN10L2: a plan preview names a watched IP
// address and range as what they are, not as domains.
func TestCTPlanPreviewNamesIPWatchesN10L2(t *testing.T) {
	for watched, want := range map[string]string{"example.com": "domain:example.com", "198.51.100.7": "ip:198.51.100.7", "2001:db8::/32": "range:2001:db8::/32"} {
		if got := ctWatchedTarget(watched); got != want {
			t.Errorf("ctWatchedTarget(%q) = %q; want %q", watched, got, want)
		}
	}
}
