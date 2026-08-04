// SPDX-License-Identifier: MPL-2.0

package api

import "trstctl.com/trstctl/internal/authz"

// The served ACME DNS-01 workflow's routes.
//
// Split out of api.go's route table when adding the upstream authorization read
// (epic B7) pushed that file past the served-surface size budget. The grouping
// is by workflow rather than by convenience: these eight routes are the entire
// operator-facing surface for domain validation — the provider catalogue, the
// tenant provider configs, the propagation preflight, and the freshness read
// that says when each identifier last actually proved control.
//
// Appended rather than spliced, which is the same shape licensedRouteRegistry
// already uses. Order is not load-bearing: http.ServeMux matches Go 1.22
// method+path patterns by specificity, and the generated OpenAPI document keys
// its paths in a map that is emitted sorted.
func (a *API) acmeDNS01Routes(dns01ProviderConfigPath []param) []route {
	return []route{
		{method: "GET", path: "/api/v1/acme/dns-01/providers", opID: "listACMEDNS01Providers", summary: "List served ACME DNS-01 provider coverage", handler: a.listACMEDNS01Providers, resSchema: "ACMEDNS01ProviderCatalog", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/acme/dns-01/provider-configs", opID: "createACMEDNS01ProviderConfig", summary: "Create a served ACME DNS-01 provider config using secret references", handler: a.createACMEDNS01ProviderConfig, reqSchema: "ACMEDNS01ProviderConfigRequest", resSchema: "ACMEDNS01ProviderConfig", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs", opID: "listACMEDNS01ProviderConfigs", summary: "List served ACME DNS-01 provider configs", handler: a.listACMEDNS01ProviderConfigs, resSchema: "ACMEDNS01ProviderConfigList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/dns-01/upstream-authorizations", opID: "listACMEUpstreamAuthorizations", summary: "List upstream ACME authorization staleness: when each identifier last actually validated vs last rode a reuse", handler: a.listACMEUpstreamAuthorizations, resSchema: "ACMEUpstreamAuthorizationList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "getACMEDNS01ProviderConfig", summary: "Get a served ACME DNS-01 provider config", handler: a.getACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, resSchema: "ACMEDNS01ProviderConfig", successCode: "200", perm: authz.IssuersRead},
		{method: "PUT", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "updateACMEDNS01ProviderConfig", summary: "Replace a served ACME DNS-01 provider config using secret references", handler: a.updateACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, reqSchema: "ACMEDNS01ProviderConfigRequest", resSchema: "ACMEDNS01ProviderConfig", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "DELETE", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "deleteACMEDNS01ProviderConfig", summary: "Delete a served ACME DNS-01 provider config", handler: a.deleteACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, successCode: "204", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/dns-01/preflight", opID: "preflightACMEDNS01", summary: "Run served DNS-01 propagation, CNAME, CAA, method, and wildcard policy preflight", handler: a.preflightACMEDNS01, reqSchema: "ACMEDNS01PreflightRequest", resSchema: "ACMEDNS01Preflight", successCode: "200", mutation: true, perm: authz.IssuersWrite},
	}
}
