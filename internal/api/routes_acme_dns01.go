// SPDX-License-Identifier: MPL-2.0

package api

import "trstctl.com/trstctl/internal/authz"

// The served ACME DNS-01 workflow's routes.
//
// Split out of api.go's route table when adding the upstream authorization read
// (epic B7) pushed that file past the served-surface size budget. The grouping
// is by workflow rather than by convenience: these twelve routes are the entire
// operator-facing surface for domain validation — the provider catalogue, the
// tenant provider configs, the evidence-only preflight, the real provider
// qualification/recovery workflow, and the freshness read that says when each
// identifier last actually proved control.
//
// Appended rather than spliced, which is the same shape licensedRouteRegistry
// already uses. Order is not load-bearing: http.ServeMux matches Go 1.22
// method+path patterns by specificity, and the generated OpenAPI document keys
// its paths in a map that is emitted sorted.
func (a *API) acmeDNS01Routes(dns01ProviderConfigPath []param) []route {
	qualificationRunPath := []param{pathUUID("run_id")}
	return []route{
		{method: "GET", path: "/api/v1/acme/dns-01/providers", opID: "listACMEDNS01Providers", summary: "List served ACME DNS-01 provider coverage", handler: a.listACMEDNS01Providers, resSchema: "ACMEDNS01ProviderCatalog", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/acme/dns-01/provider-configs", opID: "createACMEDNS01ProviderConfig", summary: "Create a served ACME DNS-01 provider config using secret references", handler: a.createACMEDNS01ProviderConfig, reqSchema: "ACMEDNS01ProviderConfigRequest", resSchema: "ACMEDNS01ProviderConfig", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs", opID: "listACMEDNS01ProviderConfigs", summary: "List served ACME DNS-01 provider configs", handler: a.listACMEDNS01ProviderConfigs, resSchema: "ACMEDNS01ProviderConfigList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/dns-01/upstream-authorizations", opID: "listACMEUpstreamAuthorizations", summary: "List upstream ACME authorization staleness: when each identifier last actually validated vs last rode a reuse", handler: a.listACMEUpstreamAuthorizations, resSchema: "ACMEUpstreamAuthorizationList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "getACMEDNS01ProviderConfig", summary: "Get a served ACME DNS-01 provider config", handler: a.getACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, resSchema: "ACMEDNS01ProviderConfig", successCode: "200", perm: authz.IssuersRead},
		{method: "PUT", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "updateACMEDNS01ProviderConfig", summary: "Replace a served ACME DNS-01 provider config using secret references", handler: a.updateACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, reqSchema: "ACMEDNS01ProviderConfigRequest", resSchema: "ACMEDNS01ProviderConfig", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "DELETE", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "deleteACMEDNS01ProviderConfig", summary: "Delete a served ACME DNS-01 provider config", handler: a.deleteACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, successCode: "204", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/dns-01/preflight", opID: "preflightACMEDNS01", summary: "Run served DNS-01 propagation, CNAME, CAA, method, and wildcard policy preflight", handler: a.preflightACMEDNS01, reqSchema: "ACMEDNS01PreflightRequest", resSchema: "ACMEDNS01Preflight", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/dns-01/provider-configs/{id}/qualification/preview", opID: "previewACMEDNS01Qualification", summary: "Review an exact DNS-01 provider test without writes, outside calls, probe generation, or signer calls", handler: a.previewACMEDNS01Qualification, pathParams: dns01ProviderConfigPath, reqSchema: "ACMEDNS01QualificationRequest", resSchema: "ACMEDNS01QualificationPreview", successCode: "200", perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/dns-01/provider-configs/{id}/qualification-runs", opID: "runACMEDNS01Qualification", summary: "Publish, verify, and clean up a server-generated DNS-01 provider probe through the production outbox", handler: a.runACMEDNS01Qualification, pathParams: dns01ProviderConfigPath, reqSchema: "ACMEDNS01QualificationRequest", resSchema: "ACMEDNS01QualificationRun", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs/{id}/qualification-runs", opID: "listACMEDNS01QualificationRuns", summary: "List sanitized durable DNS-01 provider-test history", handler: a.listACMEDNS01QualificationRuns, pathParams: dns01ProviderConfigPath, resSchema: "ACMEDNS01QualificationRunList", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/acme/dns-01/qualification-runs/{run_id}/retry-cleanup", opID: "retryACMEDNS01QualificationCleanup", summary: "Retry removal of a qualification TXT probe using server-held recovery authority", handler: a.retryACMEDNS01QualificationCleanup, pathParams: qualificationRunPath, resSchema: "ACMEDNS01QualificationRun", successCode: "200", mutation: true, perm: authz.IssuersWrite},
	}
}
