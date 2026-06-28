package api

import (
	"net/http"
)

type dns01ProviderCatalogItem struct {
	Name                      string   `json:"name"`
	DisplayName               string   `json:"display_name"`
	Kind                      string   `json:"kind"`
	Served                    bool     `json:"served"`
	PropagationPreflight      bool     `json:"propagation_preflight"`
	Conformance               string   `json:"conformance"`
	CredentialReferenceFields []string `json:"credential_reference_fields"`
	SecretFields              []string `json:"secret_fields"`
	Capabilities              []string `json:"capabilities"`
	ProviderPackage           string   `json:"provider_package"`
	Notes                     string   `json:"notes"`
}

type dns01ProviderCatalogResponse struct {
	Items []dns01ProviderCatalogItem `json:"items"`
}

var servedDNS01ProviderCatalog = []dns01ProviderCatalogItem{
	{
		Name: "route53", DisplayName: "AWS Route 53", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"hosted_zone_id", "aws_access_key_ref", "aws_secret_key_ref", "aws_session_token_ref"},
		Capabilities:              []string{"net.dial:route53.amazonaws.com"},
		ProviderPackage:           "internal/dns/route53",
		Notes:                     "UPSERT/DELETE TXT records through Route 53; request signing stays behind internal/crypto.",
	},
	{
		Name: "googledns", DisplayName: "Google Cloud DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"project", "managed_zone", "oauth_token_ref"},
		Capabilities:              []string{"net.dial:dns.googleapis.com"},
		ProviderPackage:           "internal/dns/googledns",
		Notes:                     "Posts Cloud DNS Change resources with add/delete rrsets.",
	},
	{
		Name: "azuredns", DisplayName: "Azure DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"subscription_id", "resource_group", "zone", "aad_token_ref"},
		Capabilities:              []string{"net.dial:management.azure.com"},
		ProviderPackage:           "internal/dns/azuredns",
		Notes:                     "Uses Azure DNS record-set PUT/DELETE with a scoped bearer token.",
	},
	{
		Name: "cloudflare", DisplayName: "Cloudflare DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"zone_id", "api_token_ref"},
		Capabilities:              []string{"net.dial:api.cloudflare.com"},
		ProviderPackage:           "internal/dns/cloudflare",
		Notes:                     "Lists, creates, and deletes TXT records through Cloudflare's DNS Records API.",
	},
	{
		Name: "rfc2136", DisplayName: "RFC 2136 dynamic DNS", Kind: "dynamic-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"server", "zone", "tsig_key_name", "tsig_secret_ref"},
		Capabilities:              []string{"net.dial:authoritative-dns-server"},
		ProviderPackage:           "internal/dns/rfc2136",
		Notes:                     "Sends DNS UPDATE add/delete messages with TSIG material held as secret bytes.",
	},
	{
		Name: "webhook", DisplayName: "Generic DNS webhook", Kind: "webhook",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"endpoint", "bearer_token_ref"},
		Capabilities:              []string{"net.dial:webhook-host"},
		ProviderPackage:           "internal/dns/webhook",
		Notes:                     "Calls operator-owned present/cleanup endpoints for providers outside the built-in catalog.",
	},
	{
		Name: "ns1", DisplayName: "NS1", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"zone", "api_key_ref"},
		Capabilities:              []string{"net.dial:api.nsone.net"},
		ProviderPackage:           "internal/dns/ns1",
		Notes:                     "Built-in provider beyond the CAP-ISS-02 denominator.",
	},
	{
		Name: "akamai", DisplayName: "Akamai Edge DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"contract_id", "group_id", "zone", "client_token_ref", "client_secret_ref", "access_token_ref"},
		Capabilities:              []string{"net.dial:akamai-edgedns-host"},
		ProviderPackage:           "internal/dns/akamai",
		Notes:                     "Built-in provider beyond the CAP-ISS-02 denominator.",
	},
	{
		Name: "ultradns", DisplayName: "UltraDNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"zone", "bearer_token_ref"},
		Capabilities:              []string{"net.dial:api.ultradns.com"},
		ProviderPackage:           "internal/dns/ultradns",
		Notes:                     "Built-in provider beyond the CAP-ISS-02 denominator.",
	},
	{
		Name: "acmedns", DisplayName: "acme-dns", Kind: "delegated-validation-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		CredentialReferenceFields: []string{"subdomain", "username_ref", "password_ref"},
		Capabilities:              []string{"net.dial:auth.acme-dns.io"},
		ProviderPackage:           "internal/dns/acmedns",
		Notes:                     "Delegated validation-zone provider for keeping production DNS untouched.",
	},
}

func (a *API) listACMEDNS01Providers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, dns01ProviderCatalogResponse{Items: servedDNS01ProviderCatalog})
}
