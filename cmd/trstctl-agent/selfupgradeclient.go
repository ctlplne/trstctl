// SPDX-License-Identifier: MPL-2.0

package main

import "net/netip"

// rfc1918AndULA is the private address space a self-upgrade download may reach
// (epic A5): the three RFC 1918 blocks plus IPv6 ULA. This agent runs inside
// the customer network, and an air-gapped estate's artifact mirror sits in
// exactly these ranges. Everything else the SSRF guard blocks stays blocked —
// loopback, link-local, metadata endpoints, multicast.
func rfc1918AndULA() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	}
}
