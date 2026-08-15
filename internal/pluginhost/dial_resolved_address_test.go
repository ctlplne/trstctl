// SPDX-License-Identifier: MPL-2.0

package pluginhost

import (
	"errors"
	"net/netip"
	"testing"

	"trstctl.com/trstctl/internal/netsec"
)

// TestGrantedNamesCannotResolveToTheMetadataService is the regression guard for
// the gap between "allowlist of names" and "allowlist of destinations".
//
// Grant.Allows matches the string the plugin passed; the dialer then resolves
// that name at connect time. A plugin author who controls DNS for a granted
// hostname simply points it at 169.254.169.254, and a grant that reads "may reach
// my vendor API" delivers the cloud metadata service instead. No rebinding race
// is needed — one A record does it. The old comment on dial() claimed the
// positive list made this stronger than an SSRF check, which had it backwards:
// a positive list of names constrains nothing about resolved addresses.
func TestGrantedNamesCannotResolveToTheMetadataService(t *testing.T) {
	for _, addr := range []string{
		"169.254.169.254:80", // AWS/GCP/Azure IMDS — the whole point
		"169.254.170.2:80",   // ECS task metadata
		"[fd00:ec2::254]:80", // EC2 IPv6 IMDS
		"100.64.0.1:443",     // CGNAT
		"224.0.0.1:80",       // multicast
		"0.0.0.0:80",         // unspecified
		"[fe80::1]:80",       // link-local
	} {
		if err := pluginDialControl("tcp", addr, nil); err == nil {
			t.Errorf("a plugin dial resolving to %s was permitted; a granted hostname pointing "+
				"there hands third-party code the instance credentials", addr)
		} else if !errors.Is(err, errDialAddressBlocked) {
			t.Errorf("%s was refused with an unexpected error: %v", addr, err)
		}
	}
}

// TestOperatorGrantedInternalDestinationsStillWork guards the other direction.
// Granting a plugin an internal address — an in-cluster Vault, a private
// registry — is an explicit operator decision, and the resolved-address check
// must not quietly override it. Loopback is included because the sandbox's own
// tests dial a local listener, and because a plugin talking to a sidecar on the
// same host is a real deployment shape.
func TestOperatorGrantedInternalDestinationsStillWork(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:8200",
		"[::1]:8200",
		"10.0.0.5:8200",
		"172.16.4.9:443",
		"192.168.1.20:443",
		"[fd12:3456::1]:443",
		"93.184.216.34:443", // ordinary public address
	} {
		if err := pluginDialControl("tcp", addr, nil); err != nil {
			t.Errorf("an explicitly granted destination %s was refused: %v", addr, err)
		}
	}
}

// TestDialControlRejectsMalformedAddresses keeps the control callback strict
// rather than fail-open on something it cannot parse.
func TestDialControlRejectsMalformedAddresses(t *testing.T) {
	for _, addr := range []string{"", "not-an-address", "1.2.3.4"} {
		if err := pluginDialControl("tcp", addr, nil); err == nil {
			t.Errorf("malformed address %q was permitted", addr)
		}
	}
}

// TestPluginDialControlAgreesWithNetsec pins this package's deliberately
// duplicated predicate against internal/netsec, which owns the same logic.
//
// The duplication exists because internal/connector must stay host-neutral
// (crypto boundary, pluginhost and stdlib only, per
// TestConnectorCoreStaysHostNeutral) and connector reaches pluginhost — so a
// non-test import of netsec here would drag host networking policy into the
// agent's portable core. This is a TEST import, which never ships and which the
// guard's `go list -deps` does not traverse, so it catches drift without
// widening the shipped graph.
func TestPluginDialControlAgreesWithNetsec(t *testing.T) {
	reference := netsec.SafeDialControlWithOptions(netsec.SafeClientOptions{
		AllowPrivateCIDRs: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("fc00::/7"),
		},
	})
	for _, addr := range []string{
		"169.254.169.254:80", "169.254.170.2:80", "[fd00:ec2::254]:80",
		"100.64.0.1:443", "224.0.0.1:80", "0.0.0.0:80", "[fe80::1]:80",
		"127.0.0.1:8200", "[::1]:8200", "10.0.0.5:8200", "172.16.4.9:443",
		"192.168.1.20:443", "[fd12:3456::1]:443", "93.184.216.34:443",
		"8.8.8.8:53", "172.32.0.1:443", "[2001:db8::1]:443",
	} {
		mine := pluginDialControl("tcp", addr, nil) != nil
		theirs := reference("tcp", addr, nil) != nil
		if mine != theirs {
			t.Errorf("%s: pluginhost blocks=%v, netsec blocks=%v; the duplicated predicate has drifted",
				addr, mine, theirs)
		}
	}
}
