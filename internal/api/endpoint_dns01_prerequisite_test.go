// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// The endpoint-lifecycle preview promises "ready to authorize". For an ACME
// authority that validates names with DNS-01, that promise is only true when a
// tenant DNS-01 provider config can publish the challenge. These cases pin the
// decision the preview makes so a missing prerequisite fails closed at preview
// time instead of dead-lettering asynchronously while the identity reads
// "waiting to be issued".
func TestEvaluateDNS01CoverageMirrorsWorkerSelection(t *testing.T) {
	zone := func(z string, upstream bool, methods ...string) store.ACMEDNS01ProviderConfig {
		if len(methods) == 0 {
			methods = []string{"dns-01"}
		}
		return store.ACMEDNS01ProviderConfig{Zone: z, AllowedMethods: methods, AllowUpstreamDV: upstream}
	}
	cases := []struct {
		name               string
		configs            []store.ACMEDNS01ProviderConfig
		identity           string
		covered, consented bool
	}{
		{"no configs", nil, "apache.partner-lab.example.com", false, false},
		{"zone covers and upstream consented", []store.ACMEDNS01ProviderConfig{zone("partner-lab.example.com", true)}, "apache.partner-lab.example.com", true, true},
		{"zone covers but not consented", []store.ACMEDNS01ProviderConfig{zone("partner-lab.example.com", false)}, "apache.partner-lab.example.com", true, false},
		{"other zone only", []store.ACMEDNS01ProviderConfig{zone("example.org", true)}, "apache.partner-lab.example.com", false, false},
		{"dns-01 not allowed", []store.ACMEDNS01ProviderConfig{zone("partner-lab.example.com", true, "http-01")}, "apache.partner-lab.example.com", false, false},
		{"wildcard needs wildcard consent", []store.ACMEDNS01ProviderConfig{zone("partner-lab.example.com", true)}, "*.partner-lab.example.com", false, false},
		{"challenge delegation domain covers the record name", []store.ACMEDNS01ProviderConfig{{ChallengeDomain: "_acme-challenge.apache.partner-lab.example.com", AllowedMethods: []string{"dns-01"}, AllowUpstreamDV: true}}, "apache.partner-lab.example.com", true, true},
		{"consented config wins over a non-consented sibling", []store.ACMEDNS01ProviderConfig{zone("partner-lab.example.com", false), zone("partner-lab.example.com", true)}, "apache.partner-lab.example.com", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			covered, consented := evaluateDNS01Coverage(tc.configs, tc.identity)
			if covered != tc.covered || consented != tc.consented {
				t.Fatalf("evaluateDNS01Coverage(%q) = covered %v consented %v; want covered %v consented %v", tc.identity, covered, consented, tc.covered, tc.consented)
			}
		})
	}
}

// A non-external or non-DNS-01 issuer must not be gated by provider configs.
func TestEndpointIssuerPrerequisiteSkipsNonDNS01Issuers(t *testing.T) {
	a := &API{}
	for _, issuer := range []endpointIssuerSummary{
		{Source: endpointIssuerPlatform, ID: endpointPlatformCAID},
		{Source: endpointIssuerPrivate, ID: "ca-1"},
		{Source: endpointIssuerExternal, ID: "digicert-1", upstreamDNS01: false},
	} {
		if err := a.checkEndpointIssuerValidationPrerequisites(t.Context(), "tenant", issuer, "svc.example.com"); err != nil {
			t.Fatalf("issuer %+v unexpectedly gated: %v", issuer, err)
		}
	}
}

// External authorities answer asynchronously; a host-executed connector must
// therefore keep the key on the host (executor=agent). Platform/private issuers
// and control-plane-executed connectors are not gated by this rule.
func TestExternalIssuerRequiresHostCustody(t *testing.T) {
	cases := []struct {
		name, source, connector string
		cfg                     string
		want                    bool
	}{
		{"external apache without executor", endpointIssuerExternal, "apache", `{"cert_path":"/lab/tls/apache.crt","key_path":"/lab/tls/apache.key"}`, true},
		{"external apache with agent executor", endpointIssuerExternal, "apache", `{"executor":"agent","cert_path":"/x","key_path":"/y"}`, false},
		{"external apache with control-plane executor", endpointIssuerExternal, "apache", `{"executor":"control_plane","cert_path":"/x","key_path":"/y"}`, true},
		{"platform apache without executor", endpointIssuerPlatform, "apache", `{}`, false},
		{"private nginx without executor", endpointIssuerPrivate, "nginx", `{}`, false},
		{"external cloud store (control-plane vantage)", endpointIssuerExternal, "aws-acm", `{"endpoint":"https://acm"}`, false},
		{"external f5 appliance (relay vantage)", endpointIssuerExternal, "f5", `{"endpoint":"https://f5"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := externalIssuerRequiresHostCustody(tc.source, tc.connector, json.RawMessage(tc.cfg)); got != tc.want {
				t.Fatalf("externalIssuerRequiresHostCustody(%q, %q, %s) = %v, want %v", tc.source, tc.connector, tc.cfg, got, tc.want)
			}
		})
	}
}
