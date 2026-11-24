// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"fmt"
	"net/netip"
)

var privateEgressNetworks = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("::1/128"),
}

// ParsePrivateEgressPrefix admits a CIDR only when the entire range is inside
// a private or loopback network. It prevents a broad /1 grant from covering
// public destinations while still allowing an exact local test endpoint.
func ParsePrivateEgressPrefix(raw string) (netip.Prefix, error) {
	prefix, err := ParseEgressAllowPrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, network := range privateEgressNetworks {
		if prefix.Addr().Is4() == network.Addr().Is4() &&
			prefix.Bits() >= network.Bits() && network.Contains(prefix.Addr()) {
			return prefix, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("%w: egress allowlist entry %q must stay inside a private or loopback range", ErrSSRFBlocked, raw)
}
