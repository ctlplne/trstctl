// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"strings"
	"testing"
)

// M4-L3: protocols.spiffe.opaque_token_audiences needs the published issuer
// an access token names, and lists at most 64 distinct, non-empty audiences.
func TestOpaqueTokenAudiencesAreValidatedM4L3(t *testing.T) {
	base := func(audiences ...string) Protocols {
		return Protocols{SPIFFE: SPIFFEProtocol{Enabled: true, TenantID: "11111111-1111-1111-1111-111111111111",
			TrustDomain: "m4l3.test", OIDCIssuerURL: "https://issuer.m4l3.test", OpaqueTokenAudiences: audiences}}
	}
	if errs := base("https://legacy.internal", "urn:legacy:billing").ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("valid opaque audiences rejected: %v", errs)
	}
	noIssuer := base("https://legacy.internal")
	noIssuer.SPIFFE.OIDCIssuerURL = ""
	many := make([]string, 65)
	for i := range many {
		many[i] = fmt.Sprintf("https://aud-%d.internal", i)
	}
	for name, c := range map[string]struct {
		p    Protocols
		want string
	}{
		"no issuer": {noIssuer, "needs protocols.spiffe.oidc_issuer_url"},
		"empty":     {base(""), "opaque_token_audiences[0] must be a non-empty audience"},
		"spaces":    {base(" https://legacy.internal"), "without surrounding spaces"},
		"repeated":  {base("https://legacy.internal", "https://legacy.internal"), "repeats"},
		"too many":  {base(many...), "at most 64"},
		"too long":  {base("https://" + strings.Repeat("a", 510)), "at most 512 bytes"},
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
