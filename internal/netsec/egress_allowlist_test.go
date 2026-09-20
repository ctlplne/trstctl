// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"net"
	"net/netip"
	"testing"
)

// TestDefaultRouteAllowlistDoesNotDisableTheGuard is the regression guard for the
// escape hatch that was not narrow.
//
// AllowPrivateCIDRs is documented as "the narrow escape hatch for operator-owned
// private CA/service endpoints". Nothing enforced narrow: 0.0.0.0/0 parses fine,
// contains every address, and so turned the allowlist into "reach anything not
// hard-blocked" — the SSRF guard off, while the config still reads as a
// restriction. Every one of the ~18 sites that parse this field would have had to
// catch it; enforcing at the point the prefix grants access covers all of them.
func TestDefaultRouteAllowlistDoesNotDisableTheGuard(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		probe  string
	}{
		{"ipv4 default route", "0.0.0.0/0", "10.1.2.3"},
		{"ipv6 default route", "::/0", "fd00::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := SafeClientOptions{AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix(tc.prefix)}}
			if allowedPrivateIP(net.ParseIP(tc.probe), opts) {
				t.Fatalf("%s in the allowlist granted access to %s; one entry disables the SSRF guard",
					tc.prefix, tc.probe)
			}
		})
	}
}

// TestHostBitsPrefixIsRejected covers the quieter version of the same problem:
// netip.ParsePrefix accepts 10.1.2.3/8 and Contains matches the masked form, so an
// operator who writes a single host address silently allowlists the whole /8.
func TestHostBitsPrefixIsRejected(t *testing.T) {
	opts := SafeClientOptions{AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}}
	if allowedPrivateIP(net.ParseIP("10.9.9.9"), opts) {
		t.Error("a prefix written with host bits set allowlisted an unrelated address in the same /8")
	}
	if err := ValidateEgressAllowPrefix(netip.MustParsePrefix("10.1.2.3/8")); err == nil {
		t.Error("ValidateEgressAllowPrefix accepted a prefix that means something wider than it reads")
	}
}

// TestLegitimateAllowlistStillWorks guards the other direction. This escape hatch
// exists for real deployments — a private CA on RFC1918, or a local sidecar, which
// the DoD runtime configs point at explicitly. Tightening must not break them.
func TestLegitimateAllowlistStillWorks(t *testing.T) {
	for _, tc := range []struct{ prefix, probe string }{
		{"10.0.0.0/8", "10.1.2.3"},
		{"192.168.4.0/24", "192.168.4.9"},
		{"127.0.0.0/8", "127.0.0.1"},
		{"fd00::/8", "fd00::1"},
	} {
		opts := SafeClientOptions{AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix(tc.prefix)}}
		if !allowedPrivateIP(net.ParseIP(tc.probe), opts) {
			t.Errorf("%s no longer allows %s; a legitimate operator allowlist broke", tc.prefix, tc.probe)
		}
		if err := ValidateEgressAllowPrefix(netip.MustParsePrefix(tc.prefix)); err != nil {
			t.Errorf("ValidateEgressAllowPrefix rejected the legitimate prefix %s: %v", tc.prefix, err)
		}
	}
}

// TestHardBlockedRangesStayBlockedRegardlessOfAllowlist pins the invariant the
// allowlist must never be able to override.
func TestHardBlockedRangesStayBlockedRegardlessOfAllowlist(t *testing.T) {
	for _, probe := range []string{
		"169.254.169.254", // cloud metadata
		"100.64.0.1",      // CGNAT
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
	} {
		opts := SafeClientOptions{AllowPrivateCIDRs: []netip.Prefix{
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("224.0.0.0/4"),
		}}
		if allowedPrivateIP(net.ParseIP(probe), opts) {
			t.Errorf("an explicit allowlist entry reached the hard-blocked address %s", probe)
		}
	}
}
