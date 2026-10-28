// SPDX-License-Identifier: BUSL-1.1

package segmentscan

import "testing"

// A212: Covered applies the scanner's own rule to an observed address: an exact
// hostname or address, a CIDR or an explicit range covers it; nothing is
// resolved, so a hostname is covered only by its own declaration.
func TestCoveredUsesTheScannersRule(t *testing.T) {
	declarations := []string{"10.0.0.0/24", "192.0.2.10-192.0.2.20", "api.example.test", "2001:db8::/64"}
	for observed, want := range map[string]bool{
		"10.0.0.5:443":           true,
		"10.0.1.5:443":           false,
		"192.0.2.15":             true,
		"192.0.2.21:8443":        false,
		"api.example.test:443":   true,
		"other.example.test:443": false,
		"[2001:db8::7]:443":      true,
		"[2001:db9::7]:443":      false,
	} {
		if got := Covered(declarations, observed); got != want {
			t.Errorf("Covered(%q) = %v, want %v", observed, got, want)
		}
	}
	if Covered(nil, "10.0.0.5:443") {
		t.Fatal("an address was covered with no declarations")
	}
}
