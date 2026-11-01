// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// P1: the issuer domain names come from config or one environment variable,
// and a name that is not a lowercase DNS name is refused.
func TestACMEDNSPersistIssuerDomainNames(t *testing.T) {
	var p Protocols
	applyProtocolsEnv(func(key string) string {
		if key == "TRSTCTL_PROTOCOLS_ACME_DNS_PERSIST_ISSUER_DOMAINS" {
			return "ca.example.test, pki.example.test"
		}
		return ""
	}, &p)
	if got := strings.Join(p.ACMEDNSPersist.IssuerDomainNames, ","); got != "ca.example.test,pki.example.test" {
		t.Fatalf("issuer domain names = %q", got)
	}
	if errs := validateACMEDNSPersist(p.ACMEDNSPersist); len(errs) != 0 {
		t.Fatalf("valid names refused: %v", errs)
	}
	for _, bad := range []string{"CA.example.test", "ca.example.test.", "https://ca.example.test", "ca", "*.example.test", "ca example.test"} {
		if errs := validateACMEDNSPersist(ACMEDNSPersist{IssuerDomainNames: []string{bad}}); len(errs) != 1 {
			t.Fatalf("%q accepted: %v", bad, errs)
		}
	}
	if errs := validateACMEDNSPersist(ACMEDNSPersist{IssuerDomainNames: []string{"ca.example.test", "ca.example.test"}}); len(errs) != 1 {
		t.Fatalf("a duplicate was accepted: %v", errs)
	}
}

// P1: upstream_dns_persist is an ACME option that needs upstream_dns01.
func TestUpstreamDNSPersistNeedsUpstreamDNS01(t *testing.T) {
	for _, tc := range []struct {
		cfg     ExternalCAConfig
		refused bool
	}{
		{ExternalCAConfig{Type: "letsencrypt", UpstreamDNS01: true, CAAIssuerDomain: "letsencrypt.org", UpstreamDNSPersist: true}, false},
		{ExternalCAConfig{Type: "letsencrypt", UpstreamDNSPersist: true}, true},
		{ExternalCAConfig{Type: "digicert", UpstreamDNS01: true, CAAIssuerDomain: "digicert.com", UpstreamDNSPersist: true}, true},
	} {
		refused := false
		for _, err := range validateExternalCAFieldScope("external_cas[0]", tc.cfg) {
			refused = refused || strings.Contains(err.Error(), "upstream_dns_persist")
		}
		if refused != tc.refused {
			t.Fatalf("%+v: refused=%v, want %v", tc.cfg, refused, tc.refused)
		}
	}
}
