// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"strings"
	"testing"
)

// M4-L5: protocols.spiffe.exchange_tenants lists more tenants the token
// exchange serves, each a tenant ID other than tenant_id and the others, in a
// trust domain of its own; the SPIFFE surface must be enabled.
func TestExchangeTenantsAreValidatedM4L5(t *testing.T) {
	const surface = "11111111-1111-4111-8111-111111111111"
	base := func(tenants ...SPIFFEExchangeTenant) Protocols {
		return Protocols{SPIFFE: SPIFFEProtocol{Enabled: true, TenantID: surface, TrustDomain: "m4l5.test", ExchangeTenants: tenants}}
	}
	ok := base(SPIFFEExchangeTenant{TenantID: "22222222-2222-4222-8222-222222222222", TrustDomain: "b.m4l5.test"},
		SPIFFEExchangeTenant{TenantID: "33333333-3333-4333-8333-333333333333", TrustDomain: "c-tenant_1.m4l5.test"})
	if errs := ok.ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("valid exchange tenants rejected: %v", errs)
	}
	disabled := ok
	disabled.SPIFFE.Enabled = false
	many := make([]SPIFFEExchangeTenant, 257)
	for i := range many {
		many[i] = SPIFFEExchangeTenant{TenantID: fmt.Sprintf("44444444-4444-4444-8444-%012d", i), TrustDomain: fmt.Sprintf("t%d.m4l5.test", i)}
	}
	for name, c := range map[string]struct {
		p    Protocols
		want string
	}{
		"surface off":      {disabled, "needs protocols.spiffe.enabled"},
		"not a tenant ID":  {base(SPIFFEExchangeTenant{TenantID: "acme", TrustDomain: "b.m4l5.test"}), "must be a tenant ID"},
		"the surface's":    {base(SPIFFEExchangeTenant{TenantID: surface, TrustDomain: "b.m4l5.test"}), "is protocols.spiffe.tenant_id or listed twice"},
		"the surface's td": {base(SPIFFEExchangeTenant{TenantID: "22222222-2222-4222-8222-222222222222", TrustDomain: "m4l5.test"}), "is protocols.spiffe.trust_domain or another tenant's"},
		"a URL":            {base(SPIFFEExchangeTenant{TenantID: "22222222-2222-4222-8222-222222222222", TrustDomain: "spiffe://b.m4l5.test"}), "must be a trust domain name"},
		"upper case":       {base(SPIFFEExchangeTenant{TenantID: "22222222-2222-4222-8222-222222222222", TrustDomain: "B.m4l5.test"}), "must be a trust domain name"},
		"too many":         {base(many...), "at most 256"},
	} {
		errs := c.p.ValidateTenantBindings("")
		found := false
		for _, err := range errs {
			found = found || strings.Contains(err.Error(), c.want)
		}
		if !found {
			t.Fatalf("%s: errors %v; want one naming %q", name, errs, c.want)
		}
	}
}
