// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"net/http"
	"strings"
)

// providerOperation describes the separately authenticated Provider namespace.
// Keep it beside the handler, rather than adding Provider routes to the core
// tenant API: a Community build must not advertise an unattached authority.
type providerOperation struct {
	method, path, id, summary, success, request, response string
	public, saml, scim                                    bool
}

var providerOperations = []providerOperation{
	{"GET", "/provider/v1/auth/methods", "getProviderAuthMethods", "List configured Provider sign-in methods", "200", "", "ProviderAuthMethods", true, false, false},
	{"GET", "/provider/v1/auth/session", "getProviderSession", "Read the authenticated Provider operator and current authority", "200", "", "ProviderSession", false, false, false},
	{"GET", "/provider/v1/auth/saml/login", "startProviderSAMLLogin", "Redirect to the configured Provider SAML identity provider", "302", "", "", true, true, false},
	{"POST", "/provider/v1/auth/saml/acs", "completeProviderSAMLLogin", "Consume a signed Provider SAML assertion and establish a session", "302", "SAMLResponse", "", true, true, false},
	{"GET", "/provider/v1/auth/saml/metadata", "getProviderSAMLMetadata", "Read Provider SAML service-provider metadata", "200", "", "SAMLMetadata", true, true, false},
	{"POST", "/provider/v1/auth/logout", "logoutProviderSession", "End the Provider browser session", "204", "", "", false, false, false},
	{"POST", "/provider/v1/tenants", "provisionProviderTenant", "Provision one delegated customer", "201", "ProviderProvisionRequest", "ProviderTenant", false, false, false},
	{"GET", "/provider/v1/tenants", "listProviderTenants", "List only delegated customers", "200", "", "ProviderTenantList", false, false, false},
	{"GET", "/provider/v1/activity", "listProviderActivity", "Read recent Provider authority and customer activity", "200", "", "ProviderActivityList", false, false, false},
	{"GET", "/provider/v1/operators", "listProviderOperators", "Read workforce lifecycle and grant episodes", "200", "", "ProviderOperatorList", false, false, false},
	{"GET", "/provider/v1/access/customers", "listProviderAccessCustomers", "List customers available to Provider access administration", "200", "", "ProviderTenantList", false, false, false},
	{"GET", "/provider/v1/evidence/verification-keys", "getProviderEvidenceVerificationKeys", "Read public invoice verification keys", "200", "", "JWKS", false, false, false},
	{"GET", "/provider/v1/tenants/{id}/health", "getProviderTenantHealth", "Read a delegated customer's narrow health snapshot", "200", "", "ProviderTenantHealth", false, false, false},
	{"GET", "/provider/v1/tenants/{id}/breakglass", "listProviderBreakGlassGrants", "List a delegated customer's bounded emergency access queue", "200", "", "ProviderBreakGlassGrantPage", false, false, false},
	{"GET", "/provider/v1/tenants/{id}/usage-evidence", "getProviderUsageEvidence", "Read signed or explicitly incomplete customer usage evidence", "200", "", "ProviderUsageEvidence", false, false, false},
	{"POST", "/provider/v1/operators/{id}/delegations", "grantProviderDelegation", "Grant exact customer operations to a Provider operator", "201", "ProviderDelegationRequest", "ProviderOperatorAccess", false, false, false},
	{"POST", "/provider/v1/operators/{id}/revocations", "revokeProviderDelegation", "Revoke exact customer operations", "200", "ProviderDelegationRequest", "ProviderOperatorAccess", false, false, false},
	{"POST", "/provider/v1/operators/{id}/role", "setProviderOperatorRole", "Set one Provider operator's role", "200", "ProviderRoleRequest", "ProviderOperatorAccess", false, false, false},
	{"POST", "/provider/v1/tenants/{id}/suspend", "suspendProviderTenant", "Suspend a delegated customer", "204", "", "", false, false, false},
	{"POST", "/provider/v1/tenants/{id}/resume", "resumeProviderTenant", "Resume a delegated customer", "204", "", "", false, false, false},
	{"POST", "/provider/v1/tenants/{id}/offboard", "offboardProviderTenant", "Begin durable customer offboarding", "204", "ProviderOffboardRequest", "", false, false, false},
	{"PUT", "/provider/v1/tenants/{id}/quota", "setProviderTenantQuota", "Set a customer quota", "204", "ProviderQuotaRequest", "", false, false, false},
	{"GET", "/provider/v1/tenants/{id}/quota", "getProviderTenantQuota", "Read a customer quota", "200", "", "ProviderQuota", false, false, false},
	{"PUT", "/provider/v1/tenants/{id}/brand", "setProviderTenantBrand", "Replace a customer brand using its current ETag", "204", "ProviderBrandRequest", "", false, false, false},
	{"GET", "/provider/v1/tenants/{id}/brand", "getProviderTenantBrand", "Read saved customer brand and revision ETag", "200", "", "ProviderBrand", false, false, false},
	{"POST", "/provider/v1/isolation-drill", "runProviderIsolationDrill", "Run the customer isolation drill", "200", "", "ProviderIsolationDrill", false, false, false},
	{"POST", "/provider/v1/breakglass", "requestProviderBreakGlass", "Request time-bounded emergency customer access", "201", "ProviderBreakGlassRequest", "ProviderBreakGlassGrant", false, false, false},
	{"POST", "/provider/v1/breakglass/{id}/consent", "consentProviderBreakGlass", "Record one distinct custodian decision", "200", "ProviderBreakGlassConsent", "ProviderBreakGlassGrant", false, false, false},
	{"POST", "/provider/v1/breakglass/{id}/results", "readProviderBreakGlassResults", "Read an active two-custodian emergency snapshot", "200", "", "ProviderTenantHealth", false, false, false},
	{"GET", "/provider/scim/v2/ServiceProviderConfig", "getProviderSCIMConfig", "Read Provider SCIM capabilities", "200", "", "ProviderSCIMConfig", false, false, true},
	{"POST", "/provider/scim/v2/Users", "createProviderSCIMUser", "Provision a Provider operator identity", "201", "ProviderSCIMUser", "ProviderSCIMUser", false, false, true},
	{"GET", "/provider/scim/v2/Users", "listProviderSCIMUsers", "List Provider operator identities", "200", "", "ProviderSCIMList", false, false, true},
	{"GET", "/provider/scim/v2/Users/{id}", "getProviderSCIMUser", "Read a Provider operator identity", "200", "", "ProviderSCIMUser", false, false, true},
	{"PUT", "/provider/scim/v2/Users/{id}", "replaceProviderSCIMUser", "Replace a Provider operator identity", "200", "ProviderSCIMUser", "ProviderSCIMUser", false, false, true},
	{"PATCH", "/provider/scim/v2/Users/{id}", "patchProviderSCIMUser", "Patch or deactivate a Provider operator identity", "200", "ProviderSCIMPatch", "ProviderSCIMUser", false, false, true},
	{"DELETE", "/provider/scim/v2/Users/{id}", "deactivateProviderSCIMUser", "Deactivate a Provider operator and revoke its authority", "204", "", "", false, false, true},
	{"GET", "/provider/scim/v2/Groups", "listProviderSCIMGroups", "List Provider role groups", "200", "", "ProviderSCIMList", false, false, true},
	{"GET", "/provider/scim/v2/Groups/{id}", "getProviderSCIMGroup", "Read a Provider role group", "200", "", "ProviderSCIMGroup", false, false, true},
	{"PATCH", "/provider/scim/v2/Groups/{id}", "patchProviderSCIMGroup", "Add Provider operator role membership", "200", "ProviderSCIMPatch", "ProviderSCIMGroup", false, false, true},
}

// providerOpenAPIDocument is built from the attached Provider capabilities.
// The spec is intentionally independent of /api/v1/openapi.json: Provider
// operators and tenant principals use different credentials and permissions.
func providerOpenAPIDocument(saml, scim bool) map[string]any {
	paths := map[string]map[string]any{}
	for _, route := range providerOperations {
		if route.saml && !saml || route.scim && !scim {
			continue
		}
		method := strings.ToLower(route.method)
		op := map[string]any{
			"operationId": route.id, "summary": route.summary,
			"tags":      []string{map[bool]string{true: "Provider SCIM", false: "Provider"}[route.scim]},
			"responses": providerOpenAPIResponses(route),
		}
		params := []map[string]any{}
		if strings.Contains(route.path, "{id}") {
			params = append(params, map[string]any{"name": "id", "in": "path", "required": true,
				"description": "Exact customer, operator, grant, or SCIM resource identifier from this path.", "schema": map[string]any{"type": "string"}})
		}
		if !route.scim && route.method != http.MethodGet && !route.saml {
			params = append(params, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true,
				"description": "Caller-chosen key bound to the exact operator, method, path, and body. Reuse returns the first outcome.", "schema": map[string]any{"type": "string"}})
			params = append(params, map[string]any{"name": providerCSRFHeader, "in": "header", "required": false,
				"description": "Required with a Provider SAML browser session; must match the double-submit CSRF cookie.", "schema": map[string]any{"type": "string"}})
		}
		if route.id == "setProviderTenantBrand" {
			params = append(params, map[string]any{"name": "If-Match", "in": "header", "required": true,
				"description": "Strong ETag returned by the exact customer's preceding GET /brand.", "schema": map[string]any{"type": "string"}})
		}
		if route.id == "listProviderActivity" {
			params = append(params, map[string]any{"name": "limit", "in": "query", "required": false, "schema": map[string]any{"type": "integer", "minimum": 1}})
		}
		if route.id == "listProviderBreakGlassGrants" {
			params = append(params,
				map[string]any{"name": "limit", "in": "query", "required": false, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25}},
				map[string]any{"name": "before", "in": "query", "required": false, "description": "Last grant ID returned on the preceding page; bound to this exact customer.", "schema": map[string]any{"type": "string"}})
		}
		if route.id == "getProviderUsageEvidence" {
			for _, name := range []string{"period_start", "period_end", "format"} {
				params = append(params, map[string]any{"name": name, "in": "query", "required": name != "format", "schema": map[string]any{"type": "string"}})
			}
		}
		if len(params) != 0 {
			op["parameters"] = params
		}
		if route.request != "" {
			contentType := "application/json"
			if route.scim {
				contentType = "application/scim+json"
			}
			if route.saml {
				contentType = "application/x-www-form-urlencoded"
			}
			op["requestBody"] = map[string]any{"required": route.id != "offboardProviderTenant", "content": map[string]any{contentType: map[string]any{"schema": providerSchemaRef(route.request)}}}
		}
		if route.scim {
			op["security"] = []map[string][]string{{"ProviderSCIMBearer": {}}}
		} else if !route.public {
			op["security"] = []map[string][]string{{"ProviderBearer": {}}, {"ProviderSession": {}}, {"ProviderDevelopmentSession": {}}}
		}
		if route.method == http.MethodGet {
			op["x-trstctl-read-only"] = true
		}
		if paths[route.path] == nil {
			paths[route.path] = map[string]any{}
		}
		paths[route.path][method] = op
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": "trstctl Provider API", "version": "v1", "description": "Licensed, separately authenticated Provider and optional SCIM operations. Customer tenant credentials cannot authorize these routes."},
		"paths":   paths,
		"components": map[string]any{"schemas": providerOpenAPISchemas(), "securitySchemes": map[string]any{
			"ProviderBearer":             map[string]any{"type": "http", "scheme": "bearer", "description": "Provider IdP bearer with verified role and MFA claims."},
			"ProviderSession":            map[string]any{"type": "apiKey", "in": "cookie", "name": providerSessionCookie, "description": "Separate HTTPS Provider SAML session; mutations also require CSRF."},
			"ProviderDevelopmentSession": map[string]any{"type": "apiKey", "in": "cookie", "name": providerDevSessionCookie, "description": "Explicit loopback development-mode Provider SAML session."},
			"ProviderSCIMBearer":         map[string]any{"type": "http", "scheme": "bearer", "description": "Dedicated Provider SCIM token from a 0600 file, separate from operator sign-in."},
		}},
	}
}

func providerOpenAPIResponses(route providerOperation) map[string]any {
	contentType := "application/json"
	if route.scim {
		contentType = "application/scim+json"
	} else if route.response == "JWKS" {
		contentType = "application/jwk-set+json"
	} else if route.response == "SAMLMetadata" {
		contentType = "application/samlmetadata+xml"
	}
	success := map[string]any{"description": "Success"}
	if route.response != "" {
		success["content"] = map[string]any{contentType: map[string]any{"schema": providerSchemaRef(route.response)}}
	}
	if route.id == "getProviderUsageEvidence" {
		success["content"] = map[string]any{
			"application/json": map[string]any{"schema": providerSchemaRef(route.response)},
			"text/csv":         map[string]any{"schema": map[string]any{"type": "string"}},
		}
	}
	return map[string]any{route.success: success,
		"4XX": map[string]any{"description": "Authentication, authorization, precondition, validation, or conflict refusal"},
		"5XX": map[string]any{"description": "Server or configured dependency failure"}}
}

func providerSchemaRef(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func providerOpenAPISchemas() map[string]any {
	str := map[string]any{"type": "string"}
	integer := map[string]any{"type": "integer"}
	boolean := map[string]any{"type": "boolean"}
	time := map[string]any{"type": "string", "format": "date-time"}
	object := func(properties map[string]any, required ...string) map[string]any {
		out := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	}
	array := func(item map[string]any) map[string]any { return map[string]any{"type": "array", "items": item} }
	brand := object(map[string]any{
		"tenant_id": str, "product_name": str, "logo_data_uri": str, "login_message": str,
		"email_from_name": str, "email_footer": str, "custom_domain": str,
		"token_overrides": map[string]any{"type": "object", "additionalProperties": str}, "revision": str,
	})
	brandRequest := object(map[string]any{
		"product_name": str, "logo_data_uri": str, "login_message": str,
		"email_from_name": str, "email_footer": str, "custom_domain": str,
		"token_overrides": map[string]any{"type": "object", "additionalProperties": str},
	})
	return map[string]any{
		"ProviderAuthMethods":         object(map[string]any{"methods": array(str)}, "methods"),
		"ProviderSession":             object(map[string]any{"id": str, "email": str, "role": str, "mfa": boolean, "authority": providerSchemaRef("ProviderAuthority")}, "id", "role", "mfa", "authority"),
		"ProviderAuthority":           object(map[string]any{"available": boolean, "access_read": boolean, "access_write": boolean, "provision": boolean, "isolation_drill": boolean, "customers": map[string]any{"type": "object", "additionalProperties": providerSchemaRef("ProviderCustomerAuthority")}}),
		"ProviderCustomerAuthority":   object(map[string]any{"read_quota": boolean, "write_quota": boolean, "write_brand": boolean, "suspend": boolean, "resume": boolean, "offboard": boolean, "break_glass": boolean, "break_glass_write": boolean}),
		"ProviderProvisionRequest":    object(map[string]any{"slug": str, "name": str}, "slug", "name"),
		"ProviderTenant":              object(map[string]any{"id": str, "slug": str, "name": str, "status": str, "created_at": time, "updated_at": time}, "id", "slug", "name", "status"),
		"ProviderTenantList":          object(map[string]any{"tenants": array(providerSchemaRef("ProviderTenant"))}, "tenants"),
		"ProviderActivityList":        object(map[string]any{"items": array(providerSchemaRef("ProviderActivity"))}, "items"),
		"ProviderActivity":            object(map[string]any{"sequence": integer, "event_id": str, "type": str, "tenant_id": str, "operator_id": str, "operator_email": str, "grant_id": str, "subject": str, "reason": str, "at": time, "request_event_id": str, "offboard_state": str, "can_continue_offboard": boolean}, "sequence", "event_id", "type", "at"),
		"ProviderOperatorList":        object(map[string]any{"operators": array(providerSchemaRef("ProviderOperatorAccess"))}, "operators"),
		"ProviderOperatorAccess":      object(map[string]any{"identity": providerSchemaRef("ProviderOperatorIdentity"), "delegations": array(providerSchemaRef("ProviderDelegation"))}, "identity", "delegations"),
		"ProviderOperatorIdentity":    object(map[string]any{"id": str, "external_id": str, "user_name": str, "email": str, "display_name": str, "role": str, "active": boolean, "source": str, "created_at": time, "updated_at": time, "deprovisioned_at": time}, "id", "role", "active"),
		"ProviderDelegation":          object(map[string]any{"grant_event_id": str, "operator_id": str, "customer_id": str, "operation": str, "source": map[string]any{"type": "string", "description": "Grant entry point, distinct from the operator identity source. provider_api covers both console and direct HTTP clients; historical console values do not distinguish them."}, "granted_by": str, "granted_at": time, "expires_at": time, "last_used_at": time, "revoked_at": time, "revoked_by": str}, "grant_event_id", "operator_id", "customer_id", "operation", "granted_at"),
		"ProviderTenantHealth":        object(map[string]any{"tenant_id": str, "health": str, "active_certificates": integer, "workspace_initialized": boolean}, "tenant_id", "health", "active_certificates"),
		"ProviderUsageEvidence":       object(map[string]any{"customer_id": str, "period_start": str, "period_end": str, "lines": array(providerSchemaRef("ProviderUsageLine")), "signable": boolean, "reason": str, "observed_from": str, "observed_to": str, "reconciliation": array(map[string]any{"type": "object"}), "digest": str, "signature": object(map[string]any{"alg": str, "key_id": str, "jws": str}), "guidance": str}, "customer_id", "period_start", "period_end", "signable", "reason", "digest"),
		"ProviderUsageLine":           object(map[string]any{"meter": str, "kind": str, "value": integer}, "meter", "kind", "value"),
		"ProviderDelegationRequest":   object(map[string]any{"customer_id": str, "operations": array(str), "expires_at": time, "reason": str}, "customer_id", "operations"),
		"ProviderRoleRequest":         object(map[string]any{"role": str}, "role"),
		"ProviderOffboardRequest":     object(map[string]any{"request_event_id": str}),
		"ProviderQuota":               object(map[string]any{"tenant_id": str, "max_agents": integer, "max_certificates_stored": integer, "max_secrets_stored": integer, "updated_by": str}),
		"ProviderQuotaRequest":        object(map[string]any{"max_agents": integer, "max_certificates_stored": integer, "max_secrets_stored": integer}),
		"ProviderBrand":               brand,
		"ProviderBrandRequest":        brandRequest,
		"ProviderIsolationDrill":      object(map[string]any{"passed": boolean, "ran_at": time, "checks": array(providerSchemaRef("ProviderIsolationCheck"))}, "passed", "checks", "ran_at"),
		"ProviderIsolationCheck":      object(map[string]any{"name": str, "passed": boolean, "detail": str}, "name", "passed", "detail"),
		"ProviderBreakGlassRequest":   object(map[string]any{"tenant_id": str, "reason": str, "ttl": map[string]any{"type": "string", "description": "Go duration such as 30m; maximum 2h."}}, "tenant_id", "reason"),
		"ProviderBreakGlassConsent":   object(map[string]any{"tenant_id": str, "approve": boolean}, "tenant_id"),
		"ProviderBreakGlassGrant":     object(map[string]any{"id": str, "tenant_id": str, "operator_id": str, "operator_email": str, "reason": str, "requested_at": time, "expires_at": time, "consented_at": time, "consented_by": str, "second_consented_at": time, "second_consented_by": str, "denied_at": time, "denied_by": str, "revoked_at": time, "use_count": integer}, "id", "tenant_id", "operator_id", "requested_at", "expires_at"),
		"ProviderBreakGlassGrantView": object(map[string]any{"id": str, "tenant_id": str, "operator_id": str, "operator_email": str, "reason": str, "requested_at": time, "expires_at": time, "consented_at": time, "consented_by": str, "second_consented_at": time, "second_consented_by": str, "denied_at": time, "denied_by": str, "revoked_at": time, "use_count": integer, "state": map[string]any{"type": "string", "enum": []string{"pending", "awaiting_co_consent", "active", "denied", "withdrawn", "revoked", "expired"}}}, "id", "tenant_id", "operator_id", "requested_at", "expires_at", "state"),
		"ProviderBreakGlassGrantPage": object(map[string]any{"items": array(providerSchemaRef("ProviderBreakGlassGrantView")), "next_cursor": str}, "items"),
		"JWKS":                        object(map[string]any{"keys": array(map[string]any{"type": "object"})}, "keys"),
		"SAMLResponse":                object(map[string]any{"SAMLResponse": str, "RelayState": str}, "SAMLResponse"),
		"SAMLMetadata":                map[string]any{"type": "string", "description": "SAML service-provider XML metadata."},
		"ProviderSCIMConfig":          object(map[string]any{"schemas": array(str), "patch": map[string]any{"type": "object"}, "bulk": map[string]any{"type": "object"}, "filter": map[string]any{"type": "object"}, "changePassword": map[string]any{"type": "object"}, "sort": map[string]any{"type": "object"}, "etag": map[string]any{"type": "object"}, "authenticationSchemes": array(map[string]any{"type": "object"})}, "schemas"),
		"ProviderSCIMUser":            object(map[string]any{"schemas": array(str), "id": str, "externalId": str, "userName": str, "active": boolean, "displayName": str, "name": map[string]any{"type": "object"}, "emails": array(map[string]any{"type": "object"}), "roles": array(map[string]any{"type": "object"}), "meta": map[string]any{"type": "object"}}, "schemas", "userName"),
		"ProviderSCIMGroup":           object(map[string]any{"schemas": array(str), "id": str, "externalId": str, "displayName": str, "members": array(map[string]any{"type": "object"}), "meta": map[string]any{"type": "object"}}, "schemas", "id", "displayName"),
		"ProviderSCIMPatch":           object(map[string]any{"schemas": array(str), "Operations": array(map[string]any{"type": "object"})}, "schemas", "Operations"),
		"ProviderSCIMList":            object(map[string]any{"schemas": array(str), "totalResults": integer, "Resources": array(map[string]any{"type": "object"})}, "schemas", "totalResults", "Resources"),
	}
}
