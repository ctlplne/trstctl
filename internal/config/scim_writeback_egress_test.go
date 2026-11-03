// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A SCIM directory on a private network is reachable only through networks the
// operator lists; a literal private endpoint that is not listed is refused
// now, naming the setting, instead of failing every delivery later.
func TestSCIMWritebackPrivateEndpointNeedsItsNetworkListed(t *testing.T) {
	base := SCIMToken{WritebackEndpoint: "https://10.20.0.5/scim/v2", WritebackTokenFile: "/run/secrets/writeback"} // #nosec G101 -- fabricated fixture path, no credential (CWE-798)
	for name, tc := range map[string]struct {
		tok  SCIMToken
		want string
	}{
		"private endpoint unlisted": {base, "is a private address; list its network in auth.scim.tokens[0].writeback_private_egress_cidrs"},
		"listed elsewhere": {func() SCIMToken { t := base; t.WritebackPrivateEgressCIDRs = []string{"10.30.0.0/16"}; return t }(),
			"is a private address"},
		"public network listed": {func() SCIMToken { t := base; t.WritebackPrivateEgressCIDRs = []string{"8.8.8.0/24"}; return t }(),
			"is not a private network a directory may be granted"},
		"relative CA file": {func() SCIMToken {
			t := base
			t.WritebackPrivateEgressCIDRs = []string{"10.20.0.0/24"}
			t.WritebackCAFile = "ca.pem"
			return t
		}(), "writeback_ca_file must be an absolute path"},
		"egress without endpoint": {SCIMToken{WritebackPrivateEgressCIDRs: []string{"10.20.0.0/24"}}, "apply only with writeback_endpoint"},
	} {
		errs := validateSCIMWriteback(0, tc.tok)
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: %q; want %q", name, joined, tc.want)
		}
	}
	listed := base
	listed.WritebackPrivateEgressCIDRs = []string{"10.20.0.0/24"}
	listed.WritebackCAFile = "/etc/trstctl/directory-ca.pem"
	if errs := validateSCIMWriteback(0, listed); len(errs) != 0 {
		t.Fatalf("a listed private directory: %v", errs)
	}
	public := SCIMToken{WritebackEndpoint: "https://directory.example.com/scim/v2", WritebackTokenFile: "/run/secrets/writeback"} // #nosec G101 -- fabricated fixture path, no credential (CWE-798)
	if errs := validateSCIMWriteback(0, public); len(errs) != 0 {
		t.Fatalf("a public directory: %v", errs)
	}
}
