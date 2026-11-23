// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// Reference-shaped field names must not make an arbitrary value safe to put
// into an event, read model, or audit response.
func TestServedCR394AndCR399RejectRawCredentialReferenceValues(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	issuer := seedScopedToken(t, h.store, h.tenant, "issuers:write", "issuers:read")
	incident := seedScopedToken(t, h.store, h.tenant, "incidents:write")
	beforeDNS := servedEventCount(t, h, projections.EventACMEDNS01ProviderConfigUpserted)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", issuer, map[string]any{
		"name": "raw-dns-credential", "provider": "cloudflare",
		"credential_refs": map[string]string{"api_token_ref": "not-a-secret-reference"}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
	})
	if status != http.StatusBadRequest {
		t.Errorf("raw DNS credential reference = %d %s, want 400", status, body)
	}
	if got := servedEventCount(t, h, projections.EventACMEDNS01ProviderConfigUpserted); got != beforeDNS {
		t.Errorf("rejected DNS credential entered event log: %d -> %d", beforeDNS, got)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", issuer, map[string]any{
		"name": "raw-dns-config-credential", "provider": "cloudflare",
		"config": map[string]string{"api_token_ref": "not-a-secret-reference"}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
	})
	if status != http.StatusBadRequest {
		t.Errorf("raw DNS config credential reference = %d %s, want 400", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", issuer, map[string]any{
		"name": "raw-dns-config-reference-alias", "provider": "cloudflare",
		"config": map[string]string{"api_token_reference": "not-a-secret-reference"}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
	})
	if status != http.StatusBadRequest {
		t.Errorf("raw DNS config reference alias = %d %s, want 400", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", issuer, map[string]any{
		"name": "raw-dns-nested-reference", "provider": "cloudflare",
		"config": map[string]any{"observations": []any{map[string]string{"api_token_ref": "not-a-secret-reference"}}}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
	})
	if status != http.StatusBadRequest {
		t.Errorf("raw DNS nested reference = %d %s, want 400", status, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies/preview", issuer, map[string]any{
		"name": "raw-anchor", "provider": "intune", "scep_profile": "fleet", "scep_endpoint": "/scep",
		"trust_anchor_refs": map[string]string{"signing_ref": "not-a-secret-reference"},
	})
	if status != http.StatusBadRequest {
		t.Errorf("raw MDM trust anchor reference = %d %s, want 400", status, body)
	}

	beforeResponse := servedEventCount(t, h, projections.EventResponseIntegrationDispatched)
	for _, provider := range []string{"splunk", "jira"} {
		destination := map[string]any{ // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
			"provider": provider, "endpoint_url": "https://alerts.example.test/ingest",
			"token_ref": "not-an-env-reference",
		}
		if provider == "jira" {
			destination["project_key"] = "SEC"
		}
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/incidents/response-integrations/dispatch", incident,
			"cr399-"+provider, map[string]any{"title": "credential reference shape", "destinations": []any{destination}})
		if status != http.StatusBadRequest {
			t.Errorf("raw %s token reference = %d %s, want 400", provider, status, body)
		}
	}
	if got := servedEventCount(t, h, projections.EventResponseIntegrationDispatched); got != beforeResponse {
		t.Fatalf("rejected response token entered event log: %d -> %d", beforeResponse, got)
	}
	if got := servedEventCount(t, h, projections.EventACMEDNS01ProviderConfigUpserted); got != beforeDNS {
		t.Errorf("rejected DNS config reference entered event log: %d -> %d", beforeDNS, got)
	}
}
