// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

func TestCertbotHarnessAssemblesProductionDNSPolicyAUD73(t *testing.T) {
	const (
		domain      = "certbot.served.test"
		bearerToken = "certbot-aud73-webhook-token" // #nosec G101 -- fabricated test-only webhook credential (CWE-798)
	)
	dns := newServedDNSWebhookFixture(t, bearerToken)
	validators := acmesrv.Validators{DNS01: acmesrv.DNS01Validator{Resolver: dns}}
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		withSecretsEnabled(t, nil),
		func(d *Deps) { d.ACMEValidators = &validators },
	)
	startServedOutboxPump(t, h.srv)

	configID := seedServedCertbotDNSPolicyAUD73(t, h, dns, domain, bearerToken)
	configs, err := h.store.ListACMEDNS01ProviderConfigs(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("list Certbot DNS provider policy: %v", err)
	}
	if len(configs) != 1 || configs[0].ID != configID || configs[0].Zone != "served.test" {
		t.Fatalf("Certbot DNS provider policies = %+v, want one exact served.test policy", configs)
	}
	methods, constrained, err := h.srv.acmeDNS01.AllowedMethods(context.Background(), h.tenant, domain)
	if err != nil {
		t.Fatalf("read Certbot domain-validation policy: %v", err)
	}
	if !constrained || len(methods) != 1 || methods[0] != acmesrv.ChallengeDNS01 {
		t.Fatalf("Certbot domain policy = constrained %t methods %v, want dns-01 only", constrained, methods)
	}
	if !h.hasEvent(t, projections.EventACMEDNS01ProviderConfigUpserted) {
		t.Fatal("Certbot DNS provider policy was not created through the immutable event authority")
	}

	const keyAuthorization = "aud73-token.aud73-thumbprint"
	cleanup, err := h.srv.acmeDNS01.Present(context.Background(), h.tenant, domain, "aud73-token", keyAuthorization)
	if err != nil {
		t.Fatalf("publish through Certbot production DNS policy: %v", err)
	}
	recordName := acmesrv.DNS01RecordName(domain)
	recordValue := acmesrv.DNS01RecordValue(keyAuthorization)
	values, err := dns.LookupTXT(context.Background(), recordName)
	if err != nil {
		t.Fatalf("resolve published Certbot DNS record: %v", err)
	}
	if len(values) != 1 || values[0] != recordValue {
		t.Fatalf("published Certbot DNS values = %v, want %q", values, recordValue)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("clean up through Certbot production DNS policy: %v", err)
	}
	dns.assertPresentedAndCleaned(t, recordName, recordValue)
	if !h.hasEvent(t, projections.EventACMEDNS01RecordPresented) || !h.hasEvent(t, projections.EventACMEDNS01RecordCleaned) {
		t.Fatal("Certbot production DNS policy did not append publish and cleanup evidence")
	}

	status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/acme/dns-01/provider-configs",
		seedScopedToken(t, h.store, h.tenant, "issuers:read"), nil)
	if status != http.StatusOK {
		t.Fatalf("served Certbot DNS policy list status = %d, want 200", status)
	}
}
