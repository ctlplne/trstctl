// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func TestCR062DNS01OperatorCeilingIsPrivateAndNarrow(t *testing.T) {
	var protocols Protocols
	applyProtocolsEnv(func(key string) string {
		if key == "TRSTCTL_PROTOCOLS_ACME_DNS01_PRIVATE_EGRESS_CIDRS" {
			return "10.24.0.0/16,127.0.0.1/32"
		}
		return ""
	}, &protocols)
	if len(protocols.ACMEDNS01PrivateEgressCIDRs) != 2 {
		t.Fatalf("DNS-01 operator ceiling was not loaded: %v", protocols.ACMEDNS01PrivateEgressCIDRs)
	}
	for _, bad := range []string{"0.0.0.0/1", "169.254.169.254/32", "10.1.2.3/8"} {
		cfg := Default()
		cfg.Protocols.ACMEDNS01PrivateEgressCIDRs = []string{bad}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("DNS-01 operator ceiling admitted %s", bad)
		}
	}
}
