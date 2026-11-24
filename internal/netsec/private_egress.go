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

// PrivateEgressWithinCeiling accepts only narrow, private tenant ranges that
// fit inside an operator-owned ceiling. The returned prefixes may be handed to
// SafeClientWithOptions or SafeDialControlWithOptions after this check.
func PrivateEgressWithinCeiling(requested, ceiling []string) ([]netip.Prefix, error) {
	if len(requested) == 0 || len(requested) > 64 || len(ceiling) == 0 {
		return nil, ErrSSRFBlocked
	}
	allowed := make([]netip.Prefix, 0, len(ceiling))
	for _, raw := range ceiling {
		prefix, err := ParsePrivateEgressPrefix(raw)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, prefix)
	}
	out := make([]netip.Prefix, 0, len(requested))
	for _, raw := range requested {
		prefix, err := ParsePrivateEgressPrefix(raw)
		if err != nil {
			return nil, err
		}
		inside := false
		for _, limit := range allowed {
			if prefix.Addr().Is4() == limit.Addr().Is4() && prefix.Bits() >= limit.Bits() && limit.Contains(prefix.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			return nil, ErrSSRFBlocked
		}
		out = append(out, prefix)
	}
	return out, nil
}
