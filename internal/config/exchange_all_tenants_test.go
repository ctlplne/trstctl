// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// N5-L2: exchange_all_tenants needs the SPIFFE surface and a
// tenant_trust_domain_suffix under which each tenant's trust domain is
// <32 hex>.<suffix>; no listed exchange tenant's trust domain may fall under
// it, and the suffix alone means nothing.
func TestExchangeAllTenantsIsValidatedN5L2(t *testing.T) {
	base := func() Protocols {
		return Protocols{SPIFFE: SPIFFEProtocol{Enabled: true, TenantID: "11111111-1111-4111-8111-111111111111", TrustDomain: "n5l2.test",
			ExchangeAllTenants: true, TenantTrustDomainSuffix: "tenants.n5l2.test"}}
	}
	if errs := base().ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("a valid configuration was rejected: %v", errs)
	}
	for name, c := range map[string]struct {
		edit func(*SPIFFEProtocol)
		want string
	}{
		"no suffix":    {func(s *SPIFFEProtocol) { s.TenantTrustDomainSuffix = "" }, "tenant_trust_domain_suffix"},
		"a URL suffix": {func(s *SPIFFEProtocol) { s.TenantTrustDomainSuffix = "spiffe://tenants" }, "must be a trust domain name"},
		"too long":     {func(s *SPIFFEProtocol) { s.TenantTrustDomainSuffix = strings.Repeat("a", 223) }, "must be a trust domain name"},
		"surface off":  {func(s *SPIFFEProtocol) { s.Enabled = false }, "needs protocols.spiffe.enabled"},
		"suffix alone": {func(s *SPIFFEProtocol) { s.ExchangeAllTenants = false }, "needs protocols.spiffe.exchange_all_tenants"},
		"listed beneath": {func(s *SPIFFEProtocol) {
			s.ExchangeTenants = []SPIFFEExchangeTenant{{TenantID: "22222222-2222-4222-8222-222222222222", TrustDomain: "x.tenants.n5l2.test"}}
		}, "falls under tenant_trust_domain_suffix"},
	} {
		p := base()
		c.edit(&p.SPIFFE)
		found := false
		for _, err := range p.ValidateTenantBindings("") {
			found = found || strings.Contains(err.Error(), c.want)
		}
		if !found {
			t.Fatalf("%s: %v; want an error naming %q", name, p.ValidateTenantBindings(""), c.want)
		}
	}
}
