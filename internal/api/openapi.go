// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// The minimal subset of OpenAPI 3.1 the platform needs to describe its REST
// surface. The document is built by buildSpec from the route registry, so it is
// always consistent with what is served.

// Document is an OpenAPI 3.1 document.
type Document struct {
	OpenAPI    string              `json:"openapi"`
	Info       Info                `json:"info"`
	Paths      map[string]PathItem `json:"paths"`
	Components Components          `json:"components"`
}

// Info is the document's metadata.
type Info struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// PathItem maps a lowercase HTTP method to its operation.
type PathItem map[string]*Operation

// Operation describes one endpoint.
type Operation struct {
	OperationID        string                `json:"operationId"`
	Summary            string                `json:"summary,omitempty"`
	Deprecated         bool                  `json:"deprecated,omitempty"`
	Parameters         []Parameter           `json:"parameters,omitempty"`
	RequestBody        *RequestBody          `json:"requestBody,omitempty"`
	Responses          map[string]Response   `json:"responses"`
	Security           []map[string][]string `json:"security,omitempty"`
	XPermission        string                `json:"x-trstctl-permission,omitempty"`
	XPublicRationale   string                `json:"x-trstctl-public-rationale,omitempty"`
	XSensitiveResponse bool                  `json:"x-trstctl-sensitive-response,omitempty"`
	XAvailability      string                `json:"x-trstctl-availability,omitempty"`
	XUnavailableReason string                `json:"x-trstctl-unavailable-reason,omitempty"`
}

// Parameter is a path or query parameter.
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Required    bool    `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody describes a request payload.
type RequestBody struct {
	Required bool                 `json:"required,omitempty"`
	Content  map[string]MediaType `json:"content"`
}

// Response describes one response.
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// MediaType binds a content type to a schema.
type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}

// Components holds reusable schemas and security schemes.
type Components struct {
	Schemas         map[string]*Schema        `json:"schemas"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
}

// SecurityScheme is the OpenAPI security-scheme subset used by guarded routes.
type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Name         string `json:"name,omitempty"`
	In           string `json:"in,omitempty"`
	Description  string `json:"description,omitempty"`
}

// Schema is a (deliberately small) JSON Schema: a $ref, or an inline type.
type Schema struct {
	Ref         string             `json:"$ref,omitempty"`
	Type        string             `json:"type,omitempty"`
	Format      string             `json:"format,omitempty"`
	Description string             `json:"description,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Required    []string           `json:"required,omitempty"`
	OneOf       []*Schema          `json:"oneOf,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
	MinLength   int                `json:"minLength,omitempty"`
	MaxLength   int                `json:"maxLength,omitempty"`
	MinItems    int                `json:"minItems,omitempty"`
	MaxItems    int                `json:"maxItems,omitempty"`
	// AdditionalProperties types free-key maps (e.g. principal -> scopes).
	AdditionalProperties *Schema `json:"additionalProperties,omitempty"`
}

func ref(name string) *Schema { return &Schema{Ref: "#/components/schemas/" + name} }

func str() *Schema       { return &Schema{Type: "string"} }
func uuid() *Schema      { return &Schema{Type: "string", Format: "uuid"} }
func timestamp() *Schema { return &Schema{Type: "string", Format: "date-time"} }

// SchemaRef returns a component-reference schema for licensed route schemas.
func SchemaRef(name string) *Schema { return ref(name) }

// StringSchema returns a JSON string schema for licensed route schemas.
func StringSchema() *Schema { return str() }

// IntegerSchema returns a JSON integer schema for licensed route schemas.
func IntegerSchema() *Schema { return &Schema{Type: "integer"} }

// BooleanSchema returns a JSON boolean schema for licensed route schemas.
func BooleanSchema() *Schema { return &Schema{Type: "boolean"} }

// TimestampSchema returns an RFC 3339 timestamp schema for licensed route schemas.
func TimestampSchema() *Schema { return timestamp() }

// ArraySchema returns an array schema for licensed route schemas.
func ArraySchema(items *Schema) *Schema { return &Schema{Type: "array", Items: items} }

// ObjectSchema returns an object schema for licensed route schemas.
func ObjectSchema(props map[string]*Schema, required ...string) *Schema {
	return object(props, required...)
}

func idempotencyHeaderParam() Parameter {
	return Parameter{
		Name:        "Idempotency-Key",
		In:          "header",
		Required:    true,
		Description: "Caller-supplied idempotency key; replays return the original mutation result.",
		Schema:      str(),
	}
}

// buildSpec generates the OpenAPI document from the route registry. The spec
// endpoint itself is omitted from the documented paths.
func buildSpec(routes []route, extraSchemas map[string]*Schema) *Document {
	schemas := componentSchemas()
	for name, schema := range extraSchemas {
		schemas[name] = schema
	}
	doc := &Document{
		OpenAPI: "3.1.0",
		Info: Info{
			Title:       "trstctl API",
			Version:     "v1",
			Description: "Resource-oriented REST API for trstctl. Mutations require an Idempotency-Key; errors use RFC 7807 problem+json unless an operation documents a typed status receipt; lists use cursor pagination.",
		},
		Paths: map[string]PathItem{},
		Components: Components{
			Schemas: schemas,
			SecuritySchemes: map[string]SecurityScheme{
				"BearerAuth": { // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
					Type:         "http",
					Scheme:       "bearer",
					BearerFormat: "trstctl API token",
					Description:  "Hashed API token resolved to a tenant-scoped principal with named trstctl permissions.",
				},
				"SessionCookie": {
					Type:        "apiKey",
					In:          "cookie",
					Name:        sessionCookieName,
					Description: "Verified browser session from OIDC, SAML, or LDAP; mutating requests also require the double-submit CSRF token.",
				},
			},
		},
	}
	for _, r := range routes {
		if r.path == specPath {
			continue
		}
		// Normalize a Go ServeMux trailing-wildcard segment ("{name...}", which lets a
		// path parameter span multiple segments, e.g. a hierarchical secret name) to the
		// standard OpenAPI "{name}" template, so the published contract stays valid
		// OpenAPI while the served route still matches multi-segment values.
		docPath := openapiPath(r.path)
		pi := doc.Paths[docPath]
		if pi == nil {
			pi = PathItem{}
			doc.Paths[docPath] = pi
		}
		op := &Operation{OperationID: r.opID, Summary: r.summary, Responses: map[string]Response{}}
		if r.sensitiveResponse {
			op.XSensitiveResponse = true
		}
		if r.perm != "" {
			op.Security = []map[string][]string{{"BearerAuth": {}}, {"SessionCookie": {}}}
			op.XPermission = string(r.perm)
		} else if rationale := publicRationaleForRoute(r); rationale != "" {
			op.XPublicRationale = rationale
		}
		if r.mutation {
			op.Parameters = append(op.Parameters, idempotencyHeaderParam())
		}
		for _, pp := range r.pathParams {
			op.Parameters = append(op.Parameters, Parameter{Name: pp.name, In: "path", Required: true, Description: pp.desc, Schema: schemaForParam(pp)})
		}
		for _, q := range r.query {
			op.Parameters = append(op.Parameters, Parameter{Name: q.name, In: "query", Required: q.required, Description: q.desc, Schema: schemaForParam(q)})
		}
		if r.reqSchema != "" {
			op.RequestBody = &RequestBody{Required: !r.reqOptional, Content: map[string]MediaType{
				"application/json": {Schema: ref(r.reqSchema)},
			}}
		}
		problemContent := map[string]MediaType{"application/problem+json": {Schema: ref("Problem")}}
		if r.unavailableReason != "" {
			op.Deprecated = true
			op.XAvailability = "unavailable"
			op.XUnavailableReason = r.unavailableReason
			op.Responses["501"] = Response{Description: r.unavailableReason, Content: problemContent}
		} else {
			success := Response{Description: "success"}
			if r.resSchema != "" {
				success.Content = map[string]MediaType{"application/json": {Schema: ref(r.resSchema)}}
			}
			op.Responses[r.successCode] = success
		}
		op.Responses["4XX"] = Response{Description: "client error", Content: problemContent}
		op.Responses["5XX"] = Response{Description: "server error", Content: problemContent}
		for status, response := range r.responseOverrides {
			op.Responses[status] = response
		}
		pi[strings.ToLower(r.method)] = op
	}
	return doc
}

func secretRotationDueRunUnavailableResponse() Response {
	return Response{
		Description: "The scheduler may return a cached typed fail-stop receipt after claiming this Idempotency-Key; pre-handler or disabled-subsystem failures remain RFC 7807 problems.",
		Content: map[string]MediaType{
			"application/json":         {Schema: ref("SecretRotationDueRun")},
			"application/problem+json": {Schema: ref("Problem")},
		},
	}
}

func secretRotationUnavailableResponse() Response {
	return Response{
		Description: "Static and dynamic-lease provider rotation is unavailable until one durable worker owns every effect and compensation phase.",
		Content: map[string]MediaType{
			"application/problem+json": {Schema: ref("Problem")},
		},
	}
}

func schemaForParam(p param) *Schema {
	typ := p.typ
	if typ == "" {
		typ = "string"
	}
	return &Schema{Type: typ, Format: p.format}
}

func object(props map[string]*Schema, required ...string) *Schema {
	return &Schema{Type: "object", Properties: props, Required: required}
}

func componentSchemas() map[string]*Schema {
	capabilityLicensePosture := object(map[string]*Schema{
		"tier":  {Type: "string", Enum: []string{"community", "enterprise", "provider"}},
		"state": {Type: "string", Enum: []string{"community", "active", "grace", "read_only"}},
	}, "tier", "state")
	capabilityViewStage := object(map[string]*Schema{
		"name":       {Type: "string", Enum: []string{"discover", "understand", "configure", "preview", "execute", "observe", "recover", "verify", "automate"}},
		"completion": {Type: "string", Enum: []string{"complete", "not_applicable", "intentional_api_only", "blocked", "missing"}},
		"reason":     str(),
	}, "name", "completion")
	capabilityUnavailableAction := object(map[string]*Schema{
		"operation_id": str(),
		"code":         {Type: "string", Enum: []string{"not_attached", "not_implemented", "dependency_not_configured"}},
		"detail":       str(),
	}, "operation_id", "code", "detail")
	capabilityRuntimeOperation := object(map[string]*Schema{
		"operation_id": str(),
		"state":        {Type: "string", Enum: []string{"allowed", "scoped", "denied", "unavailable"}},
		"code":         {Type: "string", Enum: []string{"not_implemented", "dependency_not_configured"}},
		"detail":       str(),
	}, "operation_id", "state")
	capabilityViewActions := object(map[string]*Schema{
		"allowed":     {Type: "array", Items: str()},
		"scoped":      {Type: "array", Items: str()},
		"denied":      {Type: "array", Items: str()},
		"unavailable": {Type: "array", Items: ref("CapabilityUnavailableAction")},
	}, "allowed", "scoped", "denied", "unavailable")
	capabilityViewItem := object(map[string]*Schema{
		"capability_id":       str(),
		"name":                str(),
		"purpose":             str(),
		"tool":                {Type: "string", Enum: []string{"discover", "certificates", "workloads_machines", "secrets", "software_trust", "operations", "platform_integrations"}},
		"classification":      {Type: "string", Enum: []string{"primary", "supporting"}},
		"console_route":       str(),
		"maturity":            {Type: "string", Enum: []string{"absent", "api_cli_only", "observe_only", "partial_workflow", "complete_vertical_slice"}},
		"release_blocking":    {Type: "boolean"},
		"edition":             {Type: "string", Enum: []string{"core", "core_with_licensed_extensions"}},
		"runtime_state":       {Type: "string", Enum: []string{"catalog_only", "unavailable", "partially_available", "available"}},
		"authorization_state": {Type: "string", Enum: []string{"catalog_only", "none", "scoped", "partial", "full"}},
		"dependency_state":    {Type: "string", Enum: []string{"none", "documented_not_runtime_verified"}},
		"dependencies":        {Type: "array", Items: str()},
		"stages":              {Type: "array", Items: ref("CapabilityViewStage")},
		"actions":             ref("CapabilityViewActions"),
	}, "capability_id", "name", "purpose", "tool", "classification", "console_route", "maturity", "release_blocking", "edition", "runtime_state", "authorization_state", "dependency_state", "dependencies", "stages", "actions")
	capabilityView := object(map[string]*Schema{
		"schema_version":          {Type: "integer"},
		"contract_schema_version": {Type: "integer"},
		"license":                 ref("CapabilityLicensePosture"),
		"enforcement_note":        str(),
		"operations":              {Type: "array", Items: ref("CapabilityRuntimeOperation")},
		"items":                   {Type: "array", Items: ref("CapabilityViewItem")},
	}, "schema_version", "contract_schema_version", "license", "enforcement_note", "operations", "items")

	owner := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: []string{"user", "team", "workload", "service", "vendor"}},
		"name": str(), "email": str(), "created_at": timestamp(),
		"application_id": str(), "service": str(), "business_unit": str(), "environment": str(),
		"escalation_chain":      {Type: "array", Items: str()},
		"ownership_verified_at": timestamp(), "ownership_verified_by": str(),
		"ownership_complete": {Type: "boolean"}, "ownership_attested": {Type: "boolean"},
		"ownership_current": {Type: "boolean"}, "ownership_attestation_due_at": timestamp(),
		// I2 provenance. Optional, because absent must stay distinguishable from
		// recorded-and-empty: a row that predates provenance has no origin, and
		// stamping one would read like a recorded answer.
		"ownership_source": str(), "ownership_source_ref": str(),
		"ownership_source_observed_at": str(),
	}, "id", "tenant_id", "kind", "name", "escalation_chain", "ownership_complete", "ownership_attested", "ownership_current")
	ownerReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: []string{"user", "team", "workload", "service", "vendor"}}, "name": str(), "email": str(),
		"application_id": str(), "service": str(), "business_unit": str(), "environment": str(),
		"escalation_chain": {Type: "array", Items: str()},
	}, "kind", "name")
	ownershipAssignmentReq := object(map[string]*Schema{
		"owner_id": uuid(),
		"inventory_ids": {
			Type: "array", MinItems: 1, MaxItems: projections.MaxOwnershipAssignmentAssets,
			Items: &Schema{Type: "string", MinLength: 3, MaxLength: projections.MaxOwnershipAssignmentInventoryIDLength},
		},
		"reason": {Type: "string", MinLength: 1, MaxLength: projections.MaxOwnershipAssignmentReasonLength},
	}, "owner_id", "inventory_ids", "reason")
	ownershipAssignmentResult := object(map[string]*Schema{
		"owner_id": uuid(),
		"assigned": {
			Type: "array", MinItems: 1, MaxItems: projections.MaxOwnershipAssignmentAssets,
			Items: &Schema{Type: "string", MinLength: 3, MaxLength: projections.MaxOwnershipAssignmentInventoryIDLength},
		},
		"assigned_by": {Type: "string", MinLength: 1, MaxLength: projections.MaxOwnershipAssignmentPrincipalLength},
		"assigned_at": timestamp(),
	}, "owner_id", "assigned", "assigned_by", "assigned_at")
	ownershipException := object(map[string]*Schema{
		"id": uuid(), "identity_id": uuid(), "reason": str(), "granted_by": str(),
		"granted_at": timestamp(), "expires_at": timestamp(), "revoked_by": str(),
		"revoked_at": timestamp(), "revocation_reason": str(), "active": {Type: "boolean"},
	}, "id", "identity_id", "reason", "granted_by", "granted_at", "expires_at", "active")
	ownershipExceptionReq := object(map[string]*Schema{"reason": str(), "expires_at": timestamp()}, "reason", "expires_at")
	ownershipExceptionRevokeReq := object(map[string]*Schema{"reason": str()}, "reason")

	issuer := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: []string{"x509_ca", "ssh_ca"}},
		"name": str(), "chain": {Type: "array", Items: str()}, "public_key": str(),
		"internal": {Type: "boolean"}, "chainless": {Type: "boolean"}, "created_at": timestamp(),
	}, "id", "kind", "name")
	issuerReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: []string{"x509_ca", "ssh_ca"}}, "name": str(),
		"chain": {Type: "array", Items: str()}, "public_key": str(), "internal": {Type: "boolean"},
	}, "kind", "name")
	protocolProfileStatus := object(map[string]*Schema{
		"profile":   {Type: "string", Enum: []string{"eval"}},
		"active":    {Type: "boolean"},
		"protocols": {Type: "array", Items: str()},
	}, "profile", "active", "protocols")
	cmpQualificationCheck := object(map[string]*Schema{
		"id": str(), "label": str(), "passed": {Type: "boolean"}, "detail": str(), "recovery": str(),
	}, "id", "label", "passed", "detail")
	cmpQualification := object(map[string]*Schema{
		"checked_at": timestamp(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"endpoint": str(), "profile": str(), "binding_mode": {Type: "string", Enum: []string{"subject-bound", "registration-authority"}},
		"client_trust_anchor_count": {Type: "integer"},
		"checks":                    {Type: "array", Items: ref("CMPQualificationCheck")},
		"preview_writes":            {Type: "array", Items: str()},
		"preview_external_effects":  {Type: "array", Items: str()},
		"preview_signer_calls":      {Type: "array", Items: str()},
		"proof":                     {Type: "array", Items: str()}, "blockers": {Type: "array", Items: str()},
	}, "checked_at", "ready", "effect_free", "endpoint", "profile", "binding_mode", "client_trust_anchor_count", "checks", "preview_writes", "preview_external_effects", "preview_signer_calls", "proof", "blockers")
	tsaQualificationCheck := object(map[string]*Schema{
		"id": str(), "label": str(), "passed": {Type: "boolean"}, "detail": str(), "recovery": str(),
	}, "id", "label", "passed", "detail")
	tsaQualification := object(map[string]*Schema{
		"checked_at": timestamp(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"endpoint": str(), "policy_oid": str(),
		"checks":                   {Type: "array", Items: ref("TSAQualificationCheck")},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"preview_signer_calls":     {Type: "array", Items: str()},
		"proof":                    {Type: "array", Items: str()}, "blockers": {Type: "array", Items: str()},
	}, "checked_at", "ready", "effect_free", "endpoint", "policy_oid", "checks", "preview_writes", "preview_external_effects", "preview_signer_calls", "proof", "blockers")
	spiffeQualificationCheck := object(map[string]*Schema{
		"id": str(), "label": str(), "passed": {Type: "boolean"}, "detail": str(), "recovery": str(),
	}, "id", "label", "passed", "detail")
	spiffeQualification := object(map[string]*Schema{
		"checked_at": timestamp(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"trust_domain": str(), "socket_uri": str(), "transport": {Type: "string", Enum: []string{"unix"}}, "socket_mode": str(),
		"registration_entry_count": {Type: "integer"}, "local_socket_deprecated": {Type: "boolean"},
		"supported_operations":     {Type: "array", Items: str()},
		"checks":                   {Type: "array", Items: ref("SPIFFEQualificationCheck")},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"preview_signer_calls":     {Type: "array", Items: str()},
		"proof":                    {Type: "array", Items: str()}, "blockers": {Type: "array", Items: str()},
		"client_boundary": str(),
	}, "checked_at", "ready", "effect_free", "trust_domain", "socket_uri", "transport", "socket_mode", "registration_entry_count", "local_socket_deprecated", "supported_operations", "checks", "preview_writes", "preview_external_effects", "preview_signer_calls", "proof", "blockers", "client_boundary")

	caSpec := object(map[string]*Schema{
		"common_name":           str(),
		"permitted_dns_domains": {Type: "array", Items: str()},
		"max_path_len":          {Type: "integer"},
		"extended_key_usages":   {Type: "array", Items: str()},
		"ttl_seconds":           {Type: "integer"},
		"signature_algorithm":   str(),
	}, "common_name")
	caCeremonyStartReq := object(map[string]*Schema{
		"operation": {Type: "string", Enum: []string{"create_root", "import_offline_root", "import_existing_ca", "create_intermediate", "create_offline_intermediate", "issue_intermediate_csr", "rekey_ca", "cross_sign_ca", "import_offline_cross_sign", "rekey_offline_root"}},
		"parent_id": uuid(), "authority_id": uuid(), "csr_pem": str(), "certificate_pem": str(),
		"target_certificate_pem": str(), "cross_certificate_pem": str(), "reverse_cross_certificate_pem": str(),
		"reason": str(), "signer_handle": str(), "threshold": {Type: "integer"}, "spec": ref("CASpec"),
	}, "operation", "threshold", "spec")
	caCeremony := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "purpose": str(), "threshold": {Type: "integer"},
		"status": str(), "approvals": {Type: "integer"}, "opener": str(), "created_at": timestamp(),
	}, "id", "tenant_id", "purpose", "threshold", "status", "approvals", "created_at")
	caCeremonyPlanAuthority := object(map[string]*Schema{
		"id": uuid(), "common_name": str(), "kind": str(), "status": str(),
	}, "id", "common_name", "kind", "status")
	caCeremonyPlanPreview := object(map[string]*Schema{
		"capability":               {Type: "string", Enum: []string{"F48"}},
		"operation":                caCeremonyStartReq.Properties["operation"],
		"ready":                    {Type: "boolean"},
		"request_fingerprint":      str(),
		"approval_threshold":       {Type: "integer"},
		"required_permission":      str(),
		"normalized_spec":          ref("CASpec"),
		"parent":                   ref("CACeremonyPlanAuthority"),
		"authority":                ref("CACeremonyPlanAuthority"),
		"changes":                  {Type: "array", Items: str()},
		"risks":                    {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"sensitive_inputs":         {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
	}, "capability", "operation", "ready", "request_fingerprint", "approval_threshold", "required_permission", "normalized_spec", "changes", "risks", "verification_steps", "sensitive_inputs", "preview_writes", "preview_external_effects")
	caCreateRootReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "spec": ref("CASpec"),
	}, "ceremony_id", "spec")
	caImportOfflineRootReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "certificate_pem": str(), "spec": ref("CASpec"),
	}, "ceremony_id", "certificate_pem", "spec")
	caImportExistingReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "certificate_pem": str(), "signer_handle": str(), "spec": ref("CASpec"),
	}, "ceremony_id", "certificate_pem", "signer_handle", "spec")
	caCreateIntermediateReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "parent_id": uuid(), "spec": ref("CASpec"),
	}, "ceremony_id", "parent_id", "spec")
	caCreateOfflineIntermediateCSRReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "spec": ref("CASpec"),
	}, "ceremony_id", "spec")
	caImportOfflineIntermediateReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "certificate_pem": str(), "spec": ref("CASpec"),
	}, "ceremony_id", "certificate_pem", "spec")
	caIssueIntermediateReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "csr_pem": str(), "spec": ref("CASpec"),
	}, "ceremony_id", "csr_pem", "spec")
	caAuthorityRotationReq := object(map[string]*Schema{
		"successor_id": uuid(), "reason": str(),
	}, "successor_id")
	caAuthorityRekeyReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "ttl_seconds": {Type: "integer"}, "reason": str(),
	}, "ceremony_id")
	caCrossSignReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "certificate_pem": str(),
	}, "ceremony_id", "certificate_pem")
	caOfflineCrossSignImportReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "target_certificate_pem": str(), "cross_certificate_pem": str(),
	}, "ceremony_id", "target_certificate_pem", "cross_certificate_pem")
	caOfflineRootRekeyReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "successor_certificate_pem": str(), "new_signed_by_previous_pem": str(),
		"previous_signed_by_new_pem": str(), "reason": str(), "spec": ref("CASpec"),
	}, "ceremony_id", "successor_certificate_pem", "new_signed_by_previous_pem", "previous_signed_by_new_pem", "reason", "spec")
	caIntermediateCSR := object(map[string]*Schema{
		"ceremony_id": uuid(), "parent_id": uuid(), "csr_pem": str(), "signer_handle": str(),
	}, "ceremony_id", "parent_id", "csr_pem", "signer_handle")
	// The CA calendar's read surface (H5). The band is computed at read time from
	// not_after, so it is a judgment about now rather than a stored value that
	// would be wrong tomorrow. An authority with no recorded expiry carries no
	// horizon at all rather than a fabricated one.
	// The agent job ledger's operations surface (A1). Counts and one age, never
	// tenant identifiers or payloads: an operator must be able to see the fabric
	// is moving without being handed anyone's data to see it.
	agentJobQueue := object(map[string]*Schema{
		"kind": str(), "enabled": {Type: "boolean"},
		"pending": {Type: "integer"}, "claimed": {Type: "integer"},
		"oldest_unclaimed_seconds": {Type: "integer"},
	}, "kind", "enabled", "pending", "claimed")
	// A3: credential-custody health. Counts and one age; no tenant, agent,
	// reference name or value appears anywhere in this shape.
	// F1: AD CS template posture. Verdict first, directory attributes as
	// supporting detail — what an operator needs is "which templates can be
	// used to become someone else", not a template list.
	adcsTemplateFinding := object(map[string]*Schema{
		"id":          str(),
		"severity":    {Type: "string", Enum: []string{"medium", "high", "critical"}},
		"summary":     str(),
		"remediation": str(),
		"published":   {Type: "boolean"},
		// F3: the attributes and values that produced the finding, so an
		// operator can check it against the template's own property page.
		"evidence": {Type: "array", Items: ref("ADCSFindingEvidence")},
	}, "id", "severity", "summary", "remediation")
	adcsFindingEvidence := object(map[string]*Schema{
		"attribute": str(), "observed": str(),
	}, "attribute", "observed")
	adcsTemplate := object(map[string]*Schema{
		"domain": str(), "template": str(), "display_name": str(),
		"schema_version":        {Type: "integer"},
		"published_by":          {Type: "array", Items: str()},
		"enrollment_principals": {Type: "array", Items: str()},
		// Empty severity means no findings, which is a real state; the console
		// renders it clean rather than unknown.
		"worst_severity": {Type: "string", Enum: []string{"", "medium", "high", "critical"}},
		"findings":       {Type: "array", Items: ref("ADCSTemplateFinding")},
		"observed_by":    str(), "observed_at": timestamp(),
	}, "domain", "template", "published_by", "worst_severity", "findings", "observed_at")
	adcsEnrollmentEndpoint := object(map[string]*Schema{
		"kind":                {Type: "string", Enum: []string{"web_enrollment", "ndes", "ndes_admin"}},
		"url":                 str(),
		"state":               {Type: "string", Enum: []string{"anonymous_access", "authentication_required", "redirected", "not_found", "unreachable", "reachable_other"}},
		"http_status":         {Type: "integer"},
		"authentication":      {Type: "array", Items: str()},
		"tls_verified":        {Type: "boolean"},
		"extended_protection": {Type: "string", Enum: []string{"enabled", "disabled", "unobserved"}},
	}, "kind", "url", "state", "authentication", "tls_verified", "extended_protection")
	adcsEnrollmentService := object(map[string]*Schema{
		"domain": str(), "service": str(), "dns_name": str(),
		"enrollment_web_services":  {Type: "array", Items: str()},
		"endpoints":                {Type: "array", Items: ref("ADCSEnrollmentEndpoint")},
		"agent_restriction_state":  {Type: "string", Enum: []string{"enabled", "disabled", "unobserved"}},
		"agent_restriction_source": str(),
		"worst_severity":           {Type: "string", Enum: []string{"", "medium", "high", "critical"}},
		"findings":                 {Type: "array", Items: ref("ADCSTemplateFinding")},
		"observed_by":              str(), "observed_at": timestamp(),
	}, "domain", "service", "enrollment_web_services", "endpoints", "agent_restriction_state", "agent_restriction_source", "worst_severity", "findings", "observed_by", "observed_at")
	adcsObservedTemplate := object(map[string]*Schema{
		"name": str(), "display_name": str(), "oid": str(), "schema_version": {Type: "integer"},
		"enrollee_supplies_subject": {Type: "boolean"}, "enrollee_supplies_san": {Type: "boolean"},
		"requires_manager_approval": {Type: "boolean"}, "exportable_key": {Type: "boolean"},
		"ekus": {Type: "array", Items: str()}, "enrollment_principals": {Type: "array", Items: str()},
		"published_by": {Type: "array", Items: str()},
	}, "name", "enrollee_supplies_subject", "enrollee_supplies_san", "requires_manager_approval", "exportable_key")
	adcsAgentRestrictions := object(map[string]*Schema{
		"state": {Type: "string", Enum: []string{"enabled", "disabled", "unobserved"}}, "source": str(),
	}, "state", "source")
	adcsObservedService := object(map[string]*Schema{
		"name": str(), "dns_name": str(), "templates": {Type: "array", Items: str()},
		"enrollment_web_services": {Type: "array", Items: str()},
		"endpoints":               {Type: "array", Items: ref("ADCSEnrollmentEndpoint")},
		"agent_restrictions":      ref("ADCSAgentRestrictions"),
	}, "name", "agent_restrictions")
	adcsRuleFinding := object(map[string]*Schema{
		"template": str(), "resource_kind": {Type: "string", Enum: []string{"template", "enrollment_service"}},
		"resource": str(), "id": str(),
		"severity": {Type: "string", Enum: []string{"medium", "high", "critical"}},
		"summary":  str(), "remediation": str(), "published": {Type: "boolean"},
		"evidence": {Type: "array", Items: ref("ADCSFindingEvidence")},
	}, "template", "resource_kind", "resource", "id", "severity", "summary", "remediation", "published")
	adcsAuditReference := object(map[string]*Schema{
		"event_id": str(), "event_type": str(), "sequence": {Type: "integer"},
		"digest": str(), "observed_at": timestamp(),
	}, "event_id", "event_type", "sequence", "digest", "observed_at")
	adcsObservedInventory := object(map[string]*Schema{
		"templates":           {Type: "array", Items: ref("ADCSObservedTemplate")},
		"enrollment_services": {Type: "array", Items: ref("ADCSObservedService")},
	}, "templates", "enrollment_services")
	adcsComplianceObservation := object(map[string]*Schema{
		"reference": ref("ADCSAuditReference"), "run_id": str(), "source_id": str(), "domain": str(),
		"agent_id": str(), "agent_name": str(), "directory_verified": {Type: "boolean"},
		"inventory": ref("ADCSObservedInventory"), "findings": {Type: "array", Items: ref("ADCSRuleFinding")},
	}, "reference", "run_id", "source_id", "domain", "agent_id", "agent_name", "directory_verified", "inventory", "findings")
	adcsComplianceDrift := object(map[string]*Schema{
		"reference": ref("ADCSAuditReference"), "run_id": str(), "source_id": str(), "domain": str(),
		"agent_id": str(), "observed_by": str(), "direction": {Type: "string", Enum: []string{"worse", "better", "neutral"}},
		"worsened": {Type: "boolean"}, "changes": {Type: "array", Items: ref("ADCSTemplateDriftChange")},
		"lifecycle": {Type: "array", Items: ref("ADCSTemplateLifecycleChange")},
	}, "reference", "run_id", "source_id", "domain", "agent_id", "observed_by", "direction", "worsened", "changes", "lifecycle")
	adcsComplianceEvidence := object(map[string]*Schema{
		"observations": {Type: "array", Items: ref("ADCSComplianceObservation")},
		"drift":        {Type: "array", Items: ref("ADCSComplianceDrift")},
	}, "observations", "drift")
	adcsInventorySource := object(map[string]*Schema{
		"source_id": uuid(), "name": str(), "schedule_id": uuid(),
		"schedule_enabled": {Type: "boolean"}, "monitoring_interval_seconds": {Type: "integer"},
		"last_run_id":     uuid(),
		"last_run_status": {Type: "string", Enum: []string{"pending", "running", "succeeded", "failed"}},
		"last_run_error":  str(), "last_run_created_at": timestamp(), "last_run_completed_at": timestamp(),
	}, "source_id", "name", "schedule_enabled", "last_run_status")
	adcsPosture := object(map[string]*Schema{
		// observed distinguishes "no AD CS estate" from "nobody has looked",
		// which are opposite facts an empty list cannot tell apart.
		"observed":            {Type: "boolean"},
		"sources":             {Type: "array", Items: ref("ADCSInventorySource")},
		"templates":           {Type: "array", Items: ref("ADCSTemplate")},
		"enrollment_services": {Type: "array", Items: ref("ADCSEnrollmentService")},
		"critical":            {Type: "integer"}, "high": {Type: "integer"}, "medium": {Type: "integer"},
		"guidance": str(),
	}, "observed", "templates", "enrollment_services", "critical", "high", "medium", "guidance")
	adcsTemplateDriftChange := object(map[string]*Schema{
		"template": str(), "direction": {Type: "string", Enum: []string{"worse", "better", "neutral"}},
		"change": str(), "attribute": str(), "before": str(), "after": str(),
	}, "template", "direction", "change")
	adcsTemplateLifecycleChange := object(map[string]*Schema{
		"template": str(), "lifecycle": {Type: "string", Enum: []string{"added", "removed"}},
		"was_dangerous": {Type: "boolean"}, "now_dangerous": {Type: "boolean"},
	}, "template", "lifecycle")
	adcsTemplateDrift := object(map[string]*Schema{
		"id": uuid(), "run_id": uuid(), "source_id": uuid(), "domain": str(),
		"agent_id": uuid(), "observed_by": str(), "observed_at": timestamp(),
		"direction": {Type: "string", Enum: []string{"worse", "better", "neutral"}},
		"worsened":  {Type: "boolean"},
		"changes":   {Type: "array", Items: ref("ADCSTemplateDriftChange")},
		"lifecycle": {Type: "array", Items: ref("ADCSTemplateLifecycleChange")},
	}, "id", "run_id", "source_id", "domain", "agent_id", "observed_by", "observed_at", "direction", "worsened", "changes", "lifecycle")
	adcsDriftHistory := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ADCSTemplateDrift")},
	}, "items")
	agentJobRedemptions := object(map[string]*Schema{
		"live":                {Type: "integer"},
		"total":               {Type: "integer"},
		"oldest_live_seconds": {Type: "integer"},
	}, "live", "total")
	// A1: signed receipt health. Counts and one closed-set refusal reason — the
	// statement and signature themselves stay in the ledger, not on a summary.
	agentJobReceipts := object(map[string]*Schema{
		"verified":             {Type: "integer"},
		"rejected":             {Type: "integer"},
		"last_rejected_reason": str(),
		"last_rejected_at":     timestamp(),
	}, "verified", "rejected")
	agentJobPosture := object(map[string]*Schema{
		"served":          {Type: "boolean"},
		"claimable_kinds": {Type: "array", Items: str()},
		"generated_at":    timestamp(),
		"queues":          {Type: "array", Items: ref("AgentJobQueue")},
		"redemptions":     ref("AgentJobRedemptions"),
		"receipts":        ref("AgentJobReceipts"),
	}, "served", "claimable_kinds", "generated_at", "queues", "redemptions", "receipts")
	// The ACME external account binding operator surface (B4). No field here
	// carries the HMAC key in any form — the credential's secret stays byte-backed
	// in locked memory where configuration put it (AN-8).
	acmeEABCredential := object(map[string]*Schema{
		"key_id":               str(),
		"state":                {Type: "string", Enum: []string{"active", "disabled", "expired", "exhausted"}},
		"reason":               str(),
		"allowed_identifiers":  {Type: "array", Items: str()},
		"max_orders":           {Type: "integer"},
		"not_after":            timestamp(),
		"accounts_bound":       {Type: "integer"},
		"orders_created":       {Type: "integer"},
		"orders_denied":        {Type: "integer"},
		"disabled_in_config":   {Type: "boolean"},
		"disabled_by_operator": {Type: "boolean"},
		"last_used_at":         timestamp(),
	}, "key_id", "state", "accounts_bound", "orders_created", "orders_denied", "disabled_in_config", "disabled_by_operator")
	acmeEABPosture := object(map[string]*Schema{
		"served": {Type: "boolean"}, "required": {Type: "boolean"},
		"generated_at": timestamp(),
		"items":        {Type: "array", Items: ref("ACMEEABCredential")},
	}, "served", "required", "generated_at", "items")
	acmeOperatorAction := object(map[string]*Schema{
		"kind":  {Type: "string", Enum: []string{"activate_eval_profile", "connect_acme_client", "repair_prerequisites", "repair_startup_configuration"}},
		"label": str(), "detail": str(), "method": str(), "path": str(),
	}, "kind", "label", "detail")
	acmeDomainValidationActivity := object(map[string]*Schema{
		"order_id": str(), "domain": str(),
		"order_status":         {Type: "string", Enum: []string{"pending", "ready", "processing", "valid"}},
		"authorization_status": {Type: "string", Enum: []string{"pending", "valid"}},
		"challenge_methods":    {Type: "array", Items: &Schema{Type: "string", Enum: []string{"http-01", "dns-01", "tls-alpn-01", "device-attest-01"}}},
		"validated_method":     {Type: "string", Enum: []string{"http-01", "dns-01", "tls-alpn-01", "device-attest-01"}},
		"validation_skipped":   {Type: "boolean"},
		"created_at":           timestamp(),
	}, "order_id", "domain", "order_status", "authorization_status", "challenge_methods", "validation_skipped", "created_at")
	acmeOperatorPlan := object(map[string]*Schema{
		"ready": {Type: "boolean"}, "served": {Type: "boolean"}, "tenant_bound": {Type: "boolean"},
		"directory_path":    {Type: "string", Enum: []string{"/directory"}},
		"challenge_methods": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"http-01", "dns-01", "tls-alpn-01"}}},
		"eab_required":      {Type: "boolean"}, "eab_configured": {Type: "integer"}, "eab_active": {Type: "integer"},
		"dns01_provider_configs": {Type: "integer"}, "issuing_profile": str(), "issuing_profile_ready": {Type: "boolean"},
		"activation_mode":     {Type: "string", Enum: []string{"startup_configuration", "eval_profile_event"}},
		"activation_required": {Type: "boolean"}, "activation_available": {Type: "boolean"},
		"next_action": ref("ACMEOperatorAction"),
		"blockers":    {Type: "array", Items: str()}, "warnings": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()},
		"validation_activity": {Type: "array", Items: ref("ACMEDomainValidationActivity")},
		"generated_at":        timestamp(),
	}, "ready", "served", "tenant_bound", "directory_path", "challenge_methods", "eab_required", "eab_configured", "eab_active",
		"dns01_provider_configs", "issuing_profile", "issuing_profile_ready", "activation_mode", "activation_required", "activation_available",
		"next_action", "blockers", "warnings", "recovery_steps", "preview_writes", "preview_external_effects", "validation_activity", "generated_at")
	caAuthorityHorizon := object(map[string]*Schema{
		"band_months": {Type: "integer"}, "months_remaining": {Type: "integer"},
		"severity":            {Type: "string", Enum: []string{"low", "informational", "warning", "critical"}},
		"renew_by":            timestamp(),
		"validity_compressed": {Type: "boolean"},
		"leaf_validity_days":  {Type: "integer"},
		"expired":             {Type: "boolean"},
	}, "months_remaining", "severity", "validity_compressed", "leaf_validity_days", "expired")
	caAuthority := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "parent_id": uuid(), "common_name": str(),
		"kind": str(), "status": str(), "certificate_pem": str(), "signer_handle": str(),
		"serial": str(), "not_after": timestamp(), "max_path_len": {Type: "integer"},
		"permitted_dns_names": {Type: "array", Items: str()},
		"extended_key_usages": {Type: "array", Items: str()},
		"replaces_id":         uuid(),
		"created_at":          timestamp(),
		"horizon":             ref("CAAuthorityHorizon"),
	}, "id", "tenant_id", "common_name", "kind", "status", "certificate_pem", "signer_handle", "serial", "max_path_len", "created_at")
	caAuthorityRotationIssuer := object(map[string]*Schema{
		"authority_id": uuid(), "role": str(), "status": str(), "issue_path": str(),
	}, "authority_id", "role", "status", "issue_path")
	caAuthorityRotation := object(map[string]*Schema{
		"predecessor":       ref("CAAuthority"),
		"successor":         ref("CAAuthority"),
		"issue_path":        str(),
		"active_issue_path": str(),
		"overlap_issuers":   {Type: "array", Items: ref("CAAuthorityRotationIssuer")},
	}, "predecessor", "successor", "issue_path", "active_issue_path", "overlap_issuers")
	caAuthorityRotationPlanPreview := object(map[string]*Schema{
		"capability":               {Type: "string", Enum: []string{"F48"}},
		"operation":                {Type: "string", Enum: []string{"rotate_ca"}},
		"ready":                    {Type: "boolean"},
		"request_fingerprint":      str(),
		"required_permission":      {Type: "string", Enum: []string{"issuers:write"}},
		"reason":                   str(),
		"predecessor":              ref("CACeremonyPlanAuthority"),
		"successor":                ref("CACeremonyPlanAuthority"),
		"changes":                  {Type: "array", Items: str()},
		"risks":                    {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
	}, "capability", "operation", "ready", "request_fingerprint", "required_permission", "reason", "predecessor", "successor", "changes", "risks", "verification_steps", "preview_writes", "preview_external_effects")
	caCrossSign := object(map[string]*Schema{
		"issuer_authority_id": uuid(), "target_sha256": str(), "certificate_pem": str(),
		"ceremony_id": uuid(), "imported": {Type: "boolean"},
	}, "issuer_authority_id", "target_sha256", "certificate_pem", "ceremony_id", "imported")
	caOfflineRootRekey := object(map[string]*Schema{
		"rotation": ref("CAAuthorityRotation"), "new_signed_by_previous_pem": str(),
		"previous_signed_by_new_pem": str(), "ceremony_id": uuid(),
	}, "rotation", "new_signed_by_previous_pem", "previous_signed_by_new_pem", "ceremony_id")
	caDiscoveryItem := object(map[string]*Schema{
		"id": str(), "source_id": str(), "source": {Type: "string", Enum: []string{"external_ca_registry", "ca_hierarchy"}},
		"scope": {Type: "string", Enum: []string{"public", "private"}}, "type": str(), "name": str(), "status": str(),
		"managed": {Type: "boolean"}, "parent_id": uuid(), "serial": str(), "not_after": timestamp(),
		"inventory_path": str(), "issuance_path": str(), "import_path": str(),
		"discovery_methods": {Type: "array", Items: str()},
	}, "id", "source_id", "source", "scope", "type", "name", "status", "managed", "inventory_path", "discovery_methods")
	caDiscoverySummary := object(map[string]*Schema{
		"public_count":            {Type: "integer"},
		"private_count":           {Type: "integer"},
		"external_registry_count": {Type: "integer"},
		"authority_count":         {Type: "integer"},
	}, "public_count", "private_count", "external_registry_count", "authority_count")
	caDiscoveryInventory := object(map[string]*Schema{
		"items":   {Type: "array", Items: ref("CADiscoveryItem")},
		"summary": ref("CADiscoverySummary"),
	}, "items", "summary")
	caIssueLeafReq := object(map[string]*Schema{
		"csr_pem": str(), "ttl_seconds": {Type: "integer"},
	}, "csr_pem")
	caIssuedLeaf := object(map[string]*Schema{
		"certificate_pem": str(), "serial": str(), "not_after": timestamp(),
	}, "certificate_pem", "serial", "not_after")
	caIssuedIntermediate := object(map[string]*Schema{
		"certificate_pem": str(), "serial": str(), "not_after": timestamp(),
	}, "certificate_pem", "serial", "not_after")
	externalCA := object(map[string]*Schema{
		"id": str(), "type": str(), "name": str(), "status": str(),
	}, "id", "type", "name", "status")
	externalCAIssueReq := object(map[string]*Schema{
		"csr_pem": str(), "dns_names": {Type: "array", Items: str()}, "ttl_seconds": {Type: "integer"},
		"profile_name": str(), "requested_ekus": {Type: "array", Items: str()},
	}, "csr_pem", "dns_names")
	externalCAIssued := object(map[string]*Schema{
		"certificate_pem": str(), "serial": str(), "not_after": timestamp(), "issuer": str(),
	}, "certificate_pem", "serial", "not_after", "issuer")

	identityKinds := []string{"x509_certificate", "ssh_certificate", "ssh_key", "secret", "api_key", "workload_identity"}
	identity := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: identityKinds},
		"name": str(), "owner_id": uuid(), "issuer_id": uuid(), "status": str(),
		"not_before": timestamp(), "not_after": timestamp(), "attributes": {Type: "object"}, "created_at": timestamp(),
	}, "id", "kind", "name", "owner_id", "status")
	identityReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: identityKinds}, "name": str(), "owner_id": uuid(),
		"issuer_id": uuid(), "attributes": {Type: "object"},
	}, "kind", "name", "owner_id")

	// subject_csr_pem is the CSR-first path (B1): supply your own PKCS#10 request
	// on a transition to issued and the control plane signs it rather than
	// generating a subject key, so the private key stays where you made it.
	// Omitting it keeps the deprecated server-side-keygen path, which records an
	// issuance.server_side_keygen event every time it runs.
	transitionReq := object(map[string]*Schema{
		"to":               {Type: "string", Enum: []string{"issued", "deployed", "renewing", "renewal_failed", "revoked", "retired"}},
		"reason":           str(),
		"subject_csr_pem":  {Type: "string", Description: "One public PKCS#10 CSR PEM, at most 64 KiB. A malformed nonempty CSR can return a durably replayed 400 problem with code identity_csr_rejected_before_transition and an exact tenant/subject/identity/request-key/CSR-SHA256/to/reason disposition. Only that exact disposition confirms no issuance transition was performed for this attempt; arbitrary 4xx responses do not authorize replacing an uncertain request key."},
		"expected_version": {Type: "integer"},
	}, "to")
	identityTransitionPreview := object(map[string]*Schema{
		"capability":                 str(),
		"ready":                      {Type: "boolean"},
		"identity_id":                uuid(),
		"identity_name":              str(),
		"identity_kind":              {Type: "string", Enum: identityKinds},
		"owner_id":                   uuid(),
		"owner_name":                 str(),
		"from":                       str(),
		"to":                         str(),
		"expected_version":           {Type: "integer"},
		"event_type":                 str(),
		"side_effect":                {Type: "boolean"},
		"side_effect_destination":    str(),
		"request_fingerprint":        str(),
		"required_permission":        str(),
		"prerequisites":              {Type: "array", Items: str()},
		"preview_writes":             {Type: "array", Items: str()},
		"preview_external_effects":   {Type: "array", Items: str()},
		"execution_writes":           {Type: "array", Items: str()},
		"execution_external_effects": {Type: "array", Items: str()},
		"verification_steps":         {Type: "array", Items: str()},
		"warnings":                   {Type: "array", Items: str()},
		"guidance":                   str(),
	}, "capability", "ready", "identity_id", "identity_name", "identity_kind", "owner_id", "from", "to", "expected_version", "event_type", "side_effect", "request_fingerprint", "required_permission", "prerequisites", "preview_writes", "preview_external_effects", "execution_writes", "execution_external_effects", "verification_steps", "warnings", "guidance")
	revocationReasons := []string{"unspecified", "keyCompromise", "caCompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aaCompromise"}
	bulkRevokeReq := object(map[string]*Schema{
		"ids":          {Type: "array", Items: uuid()},
		"identity_ids": {Type: "array", Items: uuid()},
		"certificate_ids": {Type: "array", Items: uuid(), MinItems: 1, MaxItems: projections.MaxCertificateRevocationBatch,
			Description: "Exact certificate inventory IDs, not lifecycle identity IDs. Do not combine with ids, identity_ids or identity criteria. Requires a verified served issuing authority; unsupported issuers fail per item without switching CA. removeFromCRL is not a revocation action."},
		"owner_id":  uuid(),
		"issuer_id": uuid(),
		"kind":      {Type: "string", Enum: identityKinds},
		"status":    {Type: "string", Enum: []string{"requested", "issued", "deployed", "renewing", "renewal_failed", "revoked", "retired"}},
		"reason":    {Type: "string", Enum: revocationReasons},
	}, "reason")
	bulkRevokeItem := object(map[string]*Schema{
		"id":     uuid(),
		"status": {Type: "string", Enum: []string{"revoked", "skipped", "failed"}},
		"error":  str(),
	}, "id", "status")
	bulkRevokeResult := object(map[string]*Schema{
		"total_matched": {Type: "integer"},
		"total_revoked": {Type: "integer"},
		"total_skipped": {Type: "integer"},
		"total_failed":  {Type: "integer"},
		"items":         {Type: "array", Items: ref("BulkRevokeItem")},
	}, "total_matched", "total_revoked", "total_skipped", "total_failed", "items")

	operationApprovalStatuses := []string{"pending", "approved", "denied", "expired", "superseded", "consumed"}
	operationApprovalResourceKinds := []string{"identity", "secret", "managed_key", "code_signing", "ephemeral"}
	operationApprovalActions := []string{
		"issue", "create", "rotate", "revoke", "sign", "recover", "delete",
		"managedkey:rotate", "managedkey:revoke", "managedkey:zeroize",
	}
	approvalReq := object(map[string]*Schema{
		"action":        {Type: "string", Enum: identityApprovalActions},
		"request_id":    uuid(),
		"intent_digest": str(),
	}, "action", "request_id", "intent_digest")
	approval := object(map[string]*Schema{
		"id": uuid(), "intent_digest": str(), "resource": str(),
		"action":   {Type: "string", Enum: identityApprovalActions},
		"approver": str(), "approvals": {Type: "integer"},
		"approval_count": {Type: "integer"}, "required_approvals": {Type: "integer"},
		"status": {Type: "string", Enum: operationApprovalStatuses},
	}, "id", "intent_digest", "resource", "action", "approver", "approvals", "approval_count", "required_approvals", "status")
	approvalRequestRecord := object(map[string]*Schema{
		"id": uuid(), "intent_digest": str(), "resource_id": str(), "resource_name": str(),
		"resource_kind": {Type: "string", Enum: operationApprovalResourceKinds},
		"action":        {Type: "string", Enum: operationApprovalActions}, "requester": str(),
		"from_state": str(), "to_state": str(), "target_version": str(), "reason": str(),
		"evidence_refs":      {Type: "array", Items: str()},
		"approval_count":     {Type: "integer"},
		"required_approvals": {Type: "integer"},
		"status":             {Type: "string", Enum: operationApprovalStatuses},
		"created_at":         timestamp(), "expires_at": timestamp(),
	}, "id", "intent_digest", "resource_id", "resource_name", "resource_kind", "action", "requester", "target_version", "evidence_refs", "approval_count", "required_approvals", "status", "created_at", "expires_at")
	approvalRequestList := object(map[string]*Schema{
		"items":       {Type: "array", Items: ref("PendingApprovalRequest")},
		"next_cursor": str(),
	}, "items")
	approvalDecisionInput := object(map[string]*Schema{
		"intent_digest": str(),
	}, "intent_digest")
	approvalDenialInput := object(map[string]*Schema{
		"intent_digest": str(),
		"reason":        str(),
	}, "intent_digest", "reason")
	approvalDecision := object(map[string]*Schema{
		"id": uuid(), "intent_digest": str(), "resource": str(),
		"action":   {Type: "string", Enum: operationApprovalActions},
		"approver": str(), "approvals": {Type: "integer"},
		"approval_count": {Type: "integer"}, "required_approvals": {Type: "integer"},
		"status": {Type: "string", Enum: operationApprovalStatuses},
	}, "id", "intent_digest", "resource", "action", "approver", "approvals", "approval_count", "required_approvals", "status")
	secretApprovalReq := object(map[string]*Schema{
		"action":     {Type: "string", Enum: []string{"rotate", "recover", "delete"}},
		"request_id": uuid(), "intent_digest": str(),
	}, "action", "request_id", "intent_digest")
	secretApproval := object(map[string]*Schema{
		"id": uuid(), "intent_digest": str(), "resource": str(), "action": {Type: "string", Enum: []string{"rotate", "recover", "delete"}},
		"approver": str(), "approvals": {Type: "integer"},
		"approval_count": {Type: "integer"}, "required_approvals": {Type: "integer"},
		"status": {Type: "string", Enum: operationApprovalStatuses},
	}, "id", "intent_digest", "resource", "action", "approver", "approvals", "approval_count", "required_approvals", "status")
	breakglassBundle := object(map[string]*Schema{
		"request_id": str(),
		"subject":    str(),
		"cert_der":   {Type: "string", Format: "byte"},
		"reason":     str(),
		"approvals":  {Type: "array", Items: str()},
		"issued_at":  timestamp(),
		"signature":  {Type: "string", Format: "byte"},
	}, "request_id", "subject", "cert_der", "reason", "approvals", "issued_at", "signature")
	breakglassReconcileReq := object(map[string]*Schema{
		"bundles": {Type: "array", Items: ref("BreakglassBundle")},
	}, "bundles")
	breakglassReconcileResp := object(map[string]*Schema{
		"reconciled": {Type: "integer"},
	}, "reconciled")
	// BreakglassIssueRequest is retained below as an unreferenced legacy schema so
	// the additive-only contract checker preserves the historical API shape. Live
	// operations use the two ceremony schemas and never accept caller-authored
	// approver names.
	breakglassLegacyIssueReq := object(map[string]*Schema{
		"request_id": str(), "subject": str(), "csr_der": {Type: "string", Format: "byte"},
		"reason": str(), "approvals": {Type: "array", Items: str()}, "ttl_seconds": {Type: "integer"},
	}, "request_id", "subject", "csr_der", "reason", "approvals")
	breakglassIssueIntentReq := object(map[string]*Schema{
		"request_id":  str(),
		"subject":     str(),
		"csr_der":     {Type: "string", Format: "byte"},
		"reason":      str(),
		"ttl_seconds": {Type: "integer"},
	}, "request_id", "subject", "csr_der", "reason")
	breakglassIssueExecutionReq := object(map[string]*Schema{
		"ceremony_id": uuid(),
		"request_id":  str(),
		"subject":     str(),
		"csr_der":     {Type: "string", Format: "byte"},
		"reason":      str(),
		"ttl_seconds": {Type: "integer"},
	}, "ceremony_id", "request_id", "subject", "csr_der", "reason")
	breakglassPrerequisite := object(map[string]*Schema{
		"id": str(), "ready": {Type: "boolean"}, "detail": str(), "remediation": str(),
	}, "id", "ready", "detail")
	breakglassIssuePlanPreview := object(map[string]*Schema{
		"capability": {Type: "string", Enum: []string{"F34"}}, "operation": {Type: "string", Enum: []string{"issue_breakglass"}},
		"ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"request_id": str(), "subject": str(), "reason": str(), "requested_ttl_seconds": {Type: "integer"}, "effective_ttl_seconds": {Type: "integer"},
		"csr_sha256": str(), "request_fingerprint": str(), "approval_threshold": {Type: "integer"}, "configured_operator_count": {Type: "integer"},
		"required_permission": str(), "prerequisites": {Type: "array", Items: ref("BreakglassPrerequisite")}, "blockers": {Type: "array", Items: str()},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()}, "preview_signer_calls": {Type: "array", Items: str()},
		"execution_writes": {Type: "array", Items: str()}, "execution_external_effects": {Type: "array", Items: str()}, "execution_signer_calls": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()}, "verification_steps": {Type: "array", Items: str()},
	}, "capability", "operation", "ready", "effect_free", "request_id", "subject", "reason", "requested_ttl_seconds", "effective_ttl_seconds",
		"csr_sha256", "request_fingerprint", "approval_threshold", "configured_operator_count", "required_permission", "prerequisites", "blockers",
		"preview_writes", "preview_external_effects", "preview_signer_calls", "execution_writes", "execution_external_effects", "execution_signer_calls", "recovery_steps", "verification_steps")
	breakglassIssueResp := object(map[string]*Schema{
		"bundle":           ref("BreakglassBundle"),
		"reconciled":       {Type: "integer"},
		"audit_event_type": str(),
	}, "bundle", "reconciled", "audit_event_type")
	breakglassCeremony := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "purpose": str(), "threshold": {Type: "integer"},
		"status": str(), "approvals": {Type: "integer"}, "opener": str(), "created_at": timestamp(),
	}, "id", "tenant_id", "purpose", "threshold", "status", "approvals", "created_at")
	breakglassRotationIntent := object(map[string]*Schema{
		"reason": str(), "ttl_seconds": {Type: "integer"},
	}, "reason", "ttl_seconds")
	breakglassRotationReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "reason": str(), "ttl_seconds": {Type: "integer"},
	}, "ceremony_id", "reason", "ttl_seconds")
	breakglassRotation := object(map[string]*Schema{
		"previous_signer_handle": str(), "active_signer_handle": str(),
		"previous_certificate_pem": str(), "active_certificate_pem": str(),
		"new_signed_by_previous_pem": str(), "previous_signed_by_new_pem": str(),
		"ceremony_id": uuid(), "request_digest": str(),
	}, "previous_signer_handle", "active_signer_handle", "previous_certificate_pem", "active_certificate_pem", "new_signed_by_previous_pem", "previous_signed_by_new_pem", "ceremony_id", "request_digest")
	breakglassCrossSignReq := object(map[string]*Schema{
		"ceremony_id": uuid(), "certificate_pem": str(),
	}, "certificate_pem")
	breakglassCrossSign := object(map[string]*Schema{
		"issuer_signer_handle": str(), "target_sha256": str(), "certificate_pem": str(), "ceremony_id": uuid(),
	}, "issuer_signer_handle", "target_sha256", "certificate_pem", "ceremony_id")

	list := func(item string) *Schema {
		return object(map[string]*Schema{
			"items":       {Type: "array", Items: ref(item)},
			"next_cursor": str(),
		}, "items")
	}

	problemSchema := object(map[string]*Schema{
		"type": str(), "title": str(), "status": {Type: "integer"}, "detail": str(), "instance": str(), "code": str(),
	})
	editionTiers := []string{"community", "enterprise", "provider"}
	editionStates := []string{"community", "active", "grace", "read_only"}
	featureModes := []string{"enabled", "read_only", "off"}
	editionFeature := object(map[string]*Schema{
		"name":     str(),
		"tier":     {Type: "string", Enum: editionTiers},
		"licensed": {Type: "boolean"},
		"mode":     {Type: "string", Enum: featureModes},
	}, "name", "tier", "licensed", "mode")
	fipsAlgorithmMode := object(map[string]*Schema{
		"algorithm":       str(),
		"mode":            str(),
		"use":             str(),
		"module_boundary": str(),
		"approved":        {Type: "boolean"},
	}, "algorithm", "mode", "use", "module_boundary", "approved")
	fipsNonFIPSFence := object(map[string]*Schema{
		"surface":           str(),
		"algorithms":        {Type: "array", Items: str()},
		"status_under_fips": str(),
		"reason":            str(),
		"action":            str(),
		"evidence_ref":      str(),
	}, "surface", "algorithms", "status_under_fips", "reason", "action", "evidence_ref")
	fipsCustodyValidationCertificate := object(map[string]*Schema{
		"provider":                   str(),
		"boundary":                   str(),
		"certificate_ref":            str(),
		"validation_scope":           str(),
		"status":                     str(),
		"required_for_approved_mode": {Type: "boolean"},
	}, "provider", "boundary", "certificate_ref", "validation_scope", "status", "required_for_approved_mode")
	fipsRegulatedDeploymentProfile := object(map[string]*Schema{
		"profile_id":                      str(),
		"capability_id":                   str(),
		"standard":                        str(),
		"go_fips_module":                  str(),
		"go_fips_module_selector":         str(),
		"build_target":                    str(),
		"runtime_assertions":              {Type: "array", Items: str()},
		"module_active":                   {Type: "boolean"},
		"self_test_passed":                {Type: "boolean"},
		"crypto_boundary":                 str(),
		"product_certification_status":    str(),
		"product_certification_residual":  str(),
		"approved_algorithms":             {Type: "array", Items: ref("FIPSAlgorithmMode")},
		"non_fips_fences":                 {Type: "array", Items: ref("FIPSNonFIPSFence")},
		"hsm_kms_validation_certificates": {Type: "array", Items: ref("FIPSCustodyValidationCertificate")},
		"operator_required_artifacts":     {Type: "array", Items: str()},
		"evidence_refs":                   {Type: "array", Items: str()},
	}, "profile_id", "capability_id", "standard", "go_fips_module_selector", "approved_algorithms", "non_fips_fences", "hsm_kms_validation_certificates")
	fipsStatus := object(map[string]*Schema{
		"module_active":                  {Type: "boolean"},
		"required":                       {Type: "boolean"},
		"self_test_passed":               {Type: "boolean"},
		"capability_id":                  str(),
		"validated_module_path":          {Type: "boolean"},
		"standard":                       str(),
		"module":                         str(),
		"build_target":                   str(),
		"runtime_activation":             {Type: "array", Items: str()},
		"ci_gate":                        str(),
		"crypto_boundary":                str(),
		"product_certification_residual": str(),
		"regulated_deployment_profile":   ref("FIPSRegulatedDeploymentProfile"),
	}, "module_active", "required", "self_test_passed")
	editionPackagingEntry := object(map[string]*Schema{
		"id":               str(),
		"name":             str(),
		"column":           str(),
		"buyer_fit":        str(),
		"license_boundary": str(),
		"billing":          str(),
		"included":         {Type: "array", Items: str()},
	}, "id", "name", "column", "buyer_fit", "license_boundary", "billing", "included")
	referencePriceBand := object(map[string]*Schema{
		"id":         str(),
		"label":      str(),
		"annual_usd": {Type: "integer"},
		"unit":       str(),
	}, "id", "label", "annual_usd", "unit")
	deploymentEntitlementInfo := object(map[string]*Schema{
		"deployment_id":                         str(),
		"environment":                           {Type: "string", Enum: []string{"production", "non_production"}},
		"production_units_consumed":             {Type: "integer"},
		"bundled_non_production_deployments":    {Type: "integer"},
		"registered_non_production_deployments": {Type: "integer"},
		"non_production_slots_remaining":        {Type: "integer"},
		"legacy_unbound":                        {Type: "boolean"},
	}, "environment", "production_units_consumed", "bundled_non_production_deployments", "registered_non_production_deployments", "non_production_slots_remaining", "legacy_unbound")
	usageMeterDefinition := object(map[string]*Schema{
		"name":             str(),
		"classification":   str(),
		"primary_billable": {Type: "boolean"},
		"notes":            str(),
	}, "name", "classification", "primary_billable")
	editionPackaging := object(map[string]*Schema{
		"category_label":                      str(),
		"positioning":                         str(),
		"billable_unit":                       str(),
		"provider_billing_unit":               str(),
		"no_per_certificate_billing":          {Type: "boolean"},
		"no_ephemeral_identity_billing":       {Type: "boolean"},
		"certificate_counters_classification": str(),
		"managed_boundary":                    str(),
		"pricing_posture":                     str(),
		"bundled_non_production_deployments":  {Type: "integer"},
		"non_production_support_posture":      str(),
		"reference_price_bands":               {Type: "array", Items: ref("ReferencePriceBand")},
		"evidence_rail":                       {Type: "array", Items: str()},
		"editions":                            {Type: "array", Items: ref("EditionPackagingEntry")},
		"meters":                              {Type: "array", Items: ref("UsageMeterDefinition")},
	}, "category_label", "positioning", "billable_unit", "provider_billing_unit", "no_per_certificate_billing", "no_ephemeral_identity_billing", "certificate_counters_classification", "managed_boundary", "pricing_posture", "bundled_non_production_deployments", "non_production_support_posture", "reference_price_bands", "evidence_rail", "editions", "meters")
	editionsInfo := object(map[string]*Schema{
		"tier":                   {Type: "string", Enum: editionTiers},
		"state":                  {Type: "string", Enum: editionStates},
		"customer":               str(),
		"license_id":             str(),
		"expires_at":             timestamp(),
		"read_only_at":           timestamp(),
		"deployment_entitlement": ref("DeploymentEntitlementInfo"),
		"tenant_band":            {Type: "integer"},
		"managed_customer_band":  {Type: "integer"},
		"rights":                 {Type: "array", Items: &Schema{Type: "string", Enum: []string{"self_host", "managed_service", "resale"}}},
		"features":               {Type: "array", Items: ref("EditionFeature")},
		"fips":                   ref("FIPSStatus"),
		"packaging":              ref("EditionPackaging"),
	}, "tier", "state", "features", "fips", "packaging")
	managedOfferingStatus := object(map[string]*Schema{
		"served":                {Type: "boolean"},
		"deployment_model":      str(),
		"tier":                  {Type: "string", Enum: editionTiers},
		"license_state":         {Type: "string", Enum: editionStates},
		"provider_plane_mode":   {Type: "string", Enum: featureModes},
		"tenant_band":           {Type: "integer"},
		"managed_customer_band": {Type: "integer"},
		"billing_unit":          str(),
		"managed_boundary":      str(),
		"idempotency_required":  {Type: "boolean"},
		"event_type":            str(),
		"mutation_path":         str(),
	}, "served", "deployment_model", "tier", "license_state", "provider_plane_mode", "billing_unit", "managed_boundary", "idempotency_required", "event_type", "mutation_path")
	platformRunMode := object(map[string]*Schema{
		"id":                   str(),
		"label":                str(),
		"packaging":            str(),
		"postgres_mode":        str(),
		"nats_mode":            str(),
		"signer_process_model": str(),
		"tenant_isolation":     str(),
		"intended_use":         str(),
		"evidence_refs":        {Type: "array", Items: str()},
	}, "id", "label", "packaging", "postgres_mode", "nats_mode", "signer_process_model", "tenant_isolation", "intended_use", "evidence_refs")
	platformHostArchive := object(map[string]*Schema{
		"os_arch":          str(),
		"postgres_version": str(),
		"runtime_pin":      str(),
		"runtime_check":    str(),
		"evaluation_only":  {Type: "boolean"},
	}, "os_arch", "postgres_version", "runtime_pin", "runtime_check", "evaluation_only")
	platformAirGap := object(map[string]*Schema{
		"capability":                   str(),
		"served":                       {Type: "boolean"},
		"runtime_egress_guard":         {Type: "boolean"},
		"no_phone_home_default":        {Type: "boolean"},
		"public_telemetry_fail_closed": {Type: "boolean"},
		"cloud_ai_fail_closed":         {Type: "boolean"},
		"data_residency_controls":      {Type: "array", Items: str()},
		"evidence_refs":                {Type: "array", Items: str()},
		"buyer_evidence_receipts":      {Type: "array", Items: str()},
	}, "capability", "served", "runtime_egress_guard", "no_phone_home_default", "public_telemetry_fail_closed", "cloud_ai_fail_closed", "data_residency_controls", "evidence_refs", "buyer_evidence_receipts")
	platformDistributionStatus := object(map[string]*Schema{
		"served":                   {Type: "boolean"},
		"capability":               str(),
		"capabilities":             {Type: "array", Items: str()},
		"control_plane_lineage":    str(),
		"default_evaluation_mode":  str(),
		"production_mode":          str(),
		"offline_license_verifier": {Type: "boolean"},
		"core_audit_and_export":    {Type: "boolean"},
		"run_modes":                {Type: "array", Items: ref("PlatformRunMode")},
		"supported_host_archives":  {Type: "array", Items: ref("PlatformHostArchive")},
		"air_gap":                  ref("PlatformAirGap"),
		"release_gates":            {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"buyer_evidence_receipts":  {Type: "array", Items: str()},
	}, "served", "capability", "capabilities", "control_plane_lineage", "default_evaluation_mode", "production_mode", "offline_license_verifier", "core_audit_and_export", "run_modes", "supported_host_archives", "air_gap", "release_gates", "evidence_refs", "buyer_evidence_receipts")
	enterpriseSupportTier := object(map[string]*Schema{
		"id":                   str(),
		"name":                 str(),
		"coverage":             str(),
		"initial_response_sla": str(),
		"update_cadence_sla":   str(),
		"escalation":           str(),
		"license_mode":         {Type: "string", Enum: featureModes},
		"contract_boundary":    str(),
	}, "id", "name", "coverage", "initial_response_sla", "update_cadence_sla", "escalation", "license_mode", "contract_boundary")
	enterpriseSupportSLATarget := object(map[string]*Schema{
		"severity":             str(),
		"applies_to":           str(),
		"initial_response_sla": str(),
		"update_cadence_sla":   str(),
		"target_restore":       str(),
		"escalation":           str(),
	}, "severity", "applies_to", "initial_response_sla", "update_cadence_sla", "target_restore", "escalation")
	enterpriseProfessionalService := object(map[string]*Schema{
		"id":               str(),
		"name":             str(),
		"engagement_model": str(),
		"deliverables":     {Type: "array", Items: str()},
	}, "id", "name", "engagement_model", "deliverables")
	enterpriseSupportStatus := object(map[string]*Schema{
		"served":                {Type: "boolean"},
		"capability":            str(),
		"tier":                  {Type: "string", Enum: editionTiers},
		"license_state":         {Type: "string", Enum: editionStates},
		"support_mode":          {Type: "string", Enum: featureModes},
		"license_feature":       str(),
		"contract_boundary":     str(),
		"support_tiers":         {Type: "array", Items: ref("EnterpriseSupportTier")},
		"sla_targets":           {Type: "array", Items: ref("EnterpriseSupportSLATarget")},
		"professional_services": {Type: "array", Items: ref("EnterpriseProfessionalService")},
		"evidence_refs":         {Type: "array", Items: str()},
	}, "served", "capability", "tier", "license_state", "support_mode", "license_feature", "contract_boundary", "support_tiers", "sla_targets", "professional_services", "evidence_refs")
	scaleBand := object(map[string]*Schema{
		"id":                 str(),
		"managed_credential": str(),
		"capacity_tier":      str(),
		"topology":           str(),
	}, "id", "managed_credential", "capacity_tier", "topology")
	scaleExecutionLane := object(map[string]*Schema{
		"id":                     str(),
		"subsystem":              str(),
		"worker_pool":            str(),
		"queue":                  str(),
		"bulkhead_env":           {Type: "array", Items: str()},
		"failure_mode":           str(),
		"external_side_effect":   str(),
		"replay_source":          str(),
		"scale_trigger":          str(),
		"hot_path_slo":           str(),
		"operator_control":       str(),
		"backpressure_signal":    str(),
		"measurement":            str(),
		"architecture_invariant": str(),
	}, "id", "subsystem", "worker_pool", "queue", "bulkhead_env", "failure_mode", "external_side_effect", "replay_source", "scale_trigger", "hot_path_slo", "operator_control", "backpressure_signal", "measurement", "architecture_invariant")
	scaleShardPlan := object(map[string]*Schema{
		"id":                  str(),
		"applies_to":          str(),
		"partition_key":       str(),
		"target_shard_size":   {Type: "integer"},
		"max_shard_count":     {Type: "integer"},
		"publication_surface": str(),
	}, "id", "applies_to", "partition_key", "target_shard_size", "max_shard_count", "publication_surface")
	scaleBackpressureRule := object(map[string]*Schema{
		"id":          str(),
		"applies_to":  str(),
		"limit":       str(),
		"reject_mode": str(),
		"signal":      str(),
	}, "id", "applies_to", "limit", "reject_mode", "signal")
	scaleReleaseGate := object(map[string]*Schema{
		"id":       str(),
		"command":  str(),
		"artifact": str(),
		"required": {Type: "boolean"},
	}, "id", "command", "artifact", "required")
	scaleUnitEconomics := object(map[string]*Schema{
		"estimated_cost_per_credential_usd": {Type: "number"},
		"postgres_gib_30_day":               {Type: "number"},
		"jetstream_gib_30_day":              {Type: "number"},
		"events_per_day":                    {Type: "integer"},
	}, "estimated_cost_per_credential_usd", "postgres_gib_30_day", "jetstream_gib_30_day", "events_per_day")
	scaleTenantIsolation := object(map[string]*Schema{
		"storage_enforcement": str(),
		"query_rule":          str(),
		"evidence_refs":       {Type: "array", Items: str()},
	}, "storage_enforcement", "query_rule", "evidence_refs")
	scaleDatastorePosture := object(map[string]*Schema{
		"postgres":  str(),
		"jetstream": str(),
		"rls":       str(),
		"outbox":    str(),
	}, "postgres", "jetstream", "rls", "outbox")
	scaleSignerPosture := object(map[string]*Schema{
		"process_model": str(),
		"transport":     str(),
		"scaling":       str(),
	}, "process_model", "transport", "scaling")
	scaleProjectionPosture := object(map[string]*Schema{
		"replay_floor_events_per_second": {Type: "integer"},
		"max_lag_events":                 {Type: "integer"},
		"rebuild_source":                 str(),
	}, "replay_floor_events_per_second", "max_lag_events", "rebuild_source")
	scaleHotPathSLO := object(map[string]*Schema{
		"id":                        str(),
		"hot_path":                  str(),
		"surface":                   str(),
		"owner":                     str(),
		"benchmark":                 str(),
		"p50_ms":                    {Type: "number"},
		"p95_ms":                    {Type: "number"},
		"p99_ms":                    {Type: "number"},
		"min_throughput_per_second": {Type: "number"},
		"error_budget_percent":      {Type: "number"},
		"max_queue_saturation":      {Type: "number"},
		"max_projection_lag_events": {Type: "integer"},
		"capacity_ref":              str(),
	}, "id", "hot_path", "surface", "owner", "benchmark", "p50_ms", "p95_ms", "p99_ms", "min_throughput_per_second", "error_budget_percent", "max_queue_saturation", "max_projection_lag_events", "capacity_ref")
	scaleCapacityTier := object(map[string]*Schema{
		"id":                                str(),
		"name":                              str(),
		"tenants":                           {Type: "integer"},
		"managed_credentials":               {Type: "integer"},
		"events_per_day":                    {Type: "integer"},
		"postgres_gib_30_day":               {Type: "number"},
		"jetstream_gib_30_day":              {Type: "number"},
		"control_plane_cpu":                 str(),
		"control_plane_memory_gib":          {Type: "integer"},
		"signer_cpu":                        str(),
		"signer_memory_gib":                 {Type: "integer"},
		"estimated_monthly_cost_usd":        {Type: "integer"},
		"estimated_cost_per_credential_usd": {Type: "number"},
		"notes":                             str(),
	}, "id", "name", "tenants", "managed_credentials", "events_per_day", "postgres_gib_30_day", "jetstream_gib_30_day", "control_plane_cpu", "control_plane_memory_gib", "signer_cpu", "signer_memory_gib", "estimated_monthly_cost_usd", "estimated_cost_per_credential_usd", "notes")
	scaleOrchestrationPlan := object(map[string]*Schema{
		"capability":                 str(),
		"served":                     {Type: "boolean"},
		"generated_at":               timestamp(),
		"target_credential_bands":    {Type: "array", Items: ref("ScaleBand")},
		"selected_capacity_tier":     ref("ScaleCapacityTier"),
		"hot_path_slos":              {Type: "array", Items: ref("ScaleHotPathSLO")},
		"execution_lanes":            {Type: "array", Items: ref("ScaleExecutionLane")},
		"shard_plan":                 {Type: "array", Items: ref("ScaleShardPlan")},
		"backpressure_policy":        {Type: "array", Items: ref("ScaleBackpressureRule")},
		"release_gates":              {Type: "array", Items: ref("ScaleReleaseGate")},
		"operator_actions":           {Type: "array", Items: str()},
		"residuals":                  {Type: "array", Items: str()},
		"evidence_refs":              {Type: "array", Items: str()},
		"measurement_artifacts":      {Type: "array", Items: str()},
		"estimated_daily_event_load": {Type: "integer"},
		"estimated_monthly_cost_usd": {Type: "integer"},
		"unit_economics":             ref("ScaleUnitEconomics"),
		"tenant_isolation":           ref("ScaleTenantIsolation"),
		"datastore":                  ref("ScaleDatastorePosture"),
		"signer":                     ref("ScaleSignerPosture"),
		"projection_replay":          ref("ScaleProjectionPosture"),
	}, "capability", "served", "generated_at", "target_credential_bands", "selected_capacity_tier", "hot_path_slos", "execution_lanes", "shard_plan", "backpressure_policy", "release_gates", "operator_actions", "residuals", "evidence_refs", "measurement_artifacts", "estimated_daily_event_load", "estimated_monthly_cost_usd", "unit_economics", "tenant_isolation", "datastore", "signer", "projection_replay")
	issuanceRegion := object(map[string]*Schema{
		"id":             str(),
		"region":         str(),
		"role":           str(),
		"writable_scope": str(),
		"datastore":      str(),
		"event_stream":   str(),
		"signer":         str(),
		"health_signal":  str(),
	}, "id", "region", "role", "writable_scope", "datastore", "event_stream", "signer", "health_signal")
	tenantWriteFence := object(map[string]*Schema{
		"id":               str(),
		"scope":            str(),
		"mechanism":        str(),
		"conflict_outcome": str(),
		"evidence":         str(),
	}, "id", "scope", "mechanism", "conflict_outcome", "evidence")
	regionalIssuanceLane := object(map[string]*Schema{
		"id":                  str(),
		"region":              str(),
		"accepted_traffic":    str(),
		"mutation_fence":      str(),
		"event_append":        str(),
		"outbox_mode":         str(),
		"signer_mode":         str(),
		"backpressure_signal": str(),
		"recovery":            str(),
	}, "id", "region", "accepted_traffic", "mutation_fence", "event_append", "outbox_mode", "signer_mode", "backpressure_signal", "recovery")
	regionalFailoverStep := object(map[string]*Schema{
		"id":      str(),
		"trigger": str(),
		"action":  str(),
		"gate":    str(),
	}, "id", "trigger", "action", "gate")
	activeActiveIssuancePlan := object(map[string]*Schema{
		"capability":              str(),
		"served":                  {Type: "boolean"},
		"generated_at":            timestamp(),
		"topology":                str(),
		"write_model":             str(),
		"regions":                 {Type: "array", Items: ref("IssuanceRegion")},
		"tenant_write_fences":     {Type: "array", Items: ref("TenantWriteFence")},
		"issuance_lanes":          {Type: "array", Items: ref("RegionalIssuanceLane")},
		"failover_runbook":        {Type: "array", Items: ref("RegionalFailoverStep")},
		"release_gates":           {Type: "array", Items: ref("ScaleReleaseGate")},
		"rpo_seconds":             {Type: "integer"},
		"rto_seconds":             {Type: "integer"},
		"operator_actions":        {Type: "array", Items: str()},
		"residuals":               {Type: "array", Items: str()},
		"evidence_refs":           {Type: "array", Items: str()},
		"architecture_invariants": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "topology", "write_model", "regions", "tenant_write_fences", "issuance_lanes", "failover_runbook", "release_gates", "rpo_seconds", "rto_seconds", "operator_actions", "residuals", "evidence_refs", "architecture_invariants")
	managedTenantReq := object(map[string]*Schema{
		"tenant_id":      uuid(),
		"name":           str(),
		"region":         str(),
		"data_residency": str(),
		"plan":           str(),
		"support_tier":   str(),
		"slo_tier":       str(),
	}, "tenant_id", "name")
	managedTenant := object(map[string]*Schema{
		"tenant_id":          uuid(),
		"name":               str(),
		"provider_tenant_id": uuid(),
		"deployment_model":   str(),
		"managed":            {Type: "boolean"},
		"region":             str(),
		"data_residency":     str(),
		"plan":               str(),
		"support_tier":       str(),
		"slo_tier":           str(),
		"provisioned_by":     str(),
		"created_at":         timestamp(),
		"event_sequence":     {Type: "integer"},
	}, "tenant_id", "name", "provider_tenant_id", "deployment_model", "managed", "created_at", "event_sequence")
	nhiReviewItemReq := object(map[string]*Schema{
		"item_id": uuid(), "nhi_id": str(), "nhi_kind": str(), "display_name": str(),
		"owner_ref": str(), "resource": str(), "entitlement": str(), "risk": str(),
		"evidence_refs": {Type: "array", Items: str()},
	}, "nhi_id", "nhi_kind", "resource", "entitlement")
	nhiReviewCampaignStartReq := object(map[string]*Schema{
		"id": uuid(), "name": str(), "scope": str(), "reviewer_subject": str(),
		"due_at": timestamp(), "items": {Type: "array", Items: ref("NHIReviewItemRequest")},
	}, "name", "items")
	nhiReviewDecisionReq := object(map[string]*Schema{
		"decision":         {Type: "string", Enum: []string{"certified", "revoked", "exception"}},
		"reviewer_subject": str(), "reason": str(),
		"decision_evidence_refs": {Type: "array", Items: str()},
	}, "decision")
	nhiReviewItem := object(map[string]*Schema{
		"item_id": uuid(), "nhi_id": str(), "nhi_kind": str(), "display_name": str(),
		"owner_ref": str(), "resource": str(), "entitlement": str(), "risk": str(),
		"evidence_refs": {Type: "array", Items: str()},
		"status":        {Type: "string", Enum: []string{"pending", "certified", "revoked", "exception"}},
		"decision_by":   str(), "decision_reason": str(),
		"decision_evidence_refs": {Type: "array", Items: str()},
		"decided_at":             timestamp(), "created_at": timestamp(), "updated_at": timestamp(),
	}, "item_id", "nhi_id", "nhi_kind", "display_name", "resource", "entitlement", "risk", "evidence_refs", "status", "created_at", "updated_at")
	nhiReviewCampaign := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "scope": str(),
		"reviewer_subject": str(), "requested_by": str(),
		"status":          {Type: "string", Enum: []string{"open", "completed"}},
		"due_at":          timestamp(),
		"item_count":      {Type: "integer"},
		"pending_count":   {Type: "integer"},
		"certified_count": {Type: "integer"},
		"revoked_count":   {Type: "integer"},
		"exception_count": {Type: "integer"},
		"created_at":      timestamp(),
		"updated_at":      timestamp(),
		"completed_at":    timestamp(),
		"items":           {Type: "array", Items: ref("NHIReviewItem")},
	}, "id", "tenant_id", "name", "scope", "reviewer_subject", "requested_by", "status", "item_count", "pending_count", "certified_count", "revoked_count", "exception_count", "created_at", "updated_at")
	pqcCampaignStartReq := object(map[string]*Schema{
		"id": uuid(), "name": str(), "owner": str(), "deadline": timestamp(), "wave": str(),
		"readiness_criteria": {Type: "array", Items: str()},
		"finding_ids":        {Type: "array", Items: uuid()},
	}, "name", "owner", "deadline", "wave", "readiness_criteria", "finding_ids")
	pqcCampaignUpdateReq := object(map[string]*Schema{
		"owner": str(), "deadline": timestamp(), "wave": str(),
		"readiness_criteria":      {Type: "array", Items: str()},
		"readiness_status":        {Type: "string", Enum: []string{"pending", "passed", "blocked"}},
		"readiness_evidence_refs": {Type: "array", Items: str()},
	})
	pqcCampaignReadinessReq := object(map[string]*Schema{
		"status":        {Type: "string", Enum: []string{"pending", "passed", "blocked"}},
		"evidence_refs": {Type: "array", Items: str()},
	}, "status")
	campaignFindingDispositionReq := object(map[string]*Schema{
		"disposition":      {Type: "string", Enum: []string{"remediated", "excepted"}},
		"method":           str(),
		"reason":           str(),
		"evidence_refs":    {Type: "array", Items: str()},
		"evidence_digests": {Type: "array", Items: str()},
	}, "disposition", "method", "reason", "evidence_digests")
	pqcCampaignCloseReq := object(map[string]*Schema{"closed_by": str()})
	pqcCampaignFinding := object(map[string]*Schema{
		"finding_id": uuid(), "finding_digest": str(), "readiness_digest": str(), "kind": str(), "location": str(),
		"algorithm": str(), "key_bits": {Type: "integer"}, "protocol": str(), "cipher": str(),
		"disposition":        {Type: "string", Enum: []string{"pending", "remediated", "excepted"}},
		"remediation_method": str(), "disposition_reason": str(),
		"evidence_refs":    {Type: "array", Items: str()},
		"evidence_digests": {Type: "array", Items: str()},
		"dispositioned_at": timestamp(),
	}, "finding_id", "finding_digest", "kind", "location", "disposition", "evidence_refs", "evidence_digests")
	pqcCampaignClosure := object(map[string]*Schema{
		"format": str(), "signed_closure": str(),
		"public_jwks": {Type: "object", AdditionalProperties: &Schema{}},
	}, "format", "signed_closure", "public_jwks")
	pqcCampaign := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "owner": str(),
		"deadline": timestamp(), "wave": str(),
		"readiness_criteria":            {Type: "array", Items: str()},
		"readiness_status":              {Type: "string", Enum: []string{"pending", "passed", "blocked"}},
		"readiness_evidence_refs":       {Type: "array", Items: str()},
		"status":                        {Type: "string", Enum: []string{"open", "closed"}},
		"finding_count":                 {Type: "integer"},
		"pending_count":                 {Type: "integer"},
		"remediated_count":              {Type: "integer"},
		"excepted_count":                {Type: "integer"},
		"automated_execution_available": {Type: "boolean"},
		"automated_execution_note":      str(),
		"created_at":                    timestamp(), "updated_at": timestamp(), "closed_at": timestamp(),
		"findings": {Type: "array", Items: ref("PQCMigrationCampaignFinding")},
		"closure":  ref("PQCMigrationCampaignClosure"),
	}, "id", "tenant_id", "name", "owner", "deadline", "wave", "readiness_criteria", "readiness_status", "readiness_evidence_refs", "status", "finding_count", "pending_count", "remediated_count", "excepted_count", "automated_execution_available", "automated_execution_note", "created_at", "updated_at")
	accessChangeRequestCreateReq := object(map[string]*Schema{
		"id": uuid(), "requested_action": {Type: "string", Enum: []string{"grant", "modify", "revoke", "rotate", "deploy", "break_glass"}},
		"requester_subject": str(), "nhi_id": str(), "nhi_kind": str(), "display_name": str(),
		"owner_ref": str(), "resource": str(), "entitlement": str(), "change_ref": str(),
		"change_system": str(), "change_url": str(), "risk": str(), "reason": str(),
		"evidence_refs": {Type: "array", Items: str()}, "required_approvals": {Type: "integer"},
	}, "requested_action", "nhi_id", "nhi_kind", "resource", "entitlement", "change_ref", "reason")
	accessChangeDecisionReq := object(map[string]*Schema{
		"decision":         {Type: "string", Enum: []string{"approved", "denied"}},
		"approver_subject": str(), "reason": str(),
		"decision_evidence_refs": {Type: "array", Items: str()},
	}, "decision")
	accessChangeDecision := object(map[string]*Schema{
		"request_id": uuid(), "approver_subject": str(),
		"decision": {Type: "string", Enum: []string{"approved", "denied"}},
		"reason":   str(), "decision_evidence_refs": {Type: "array", Items: str()},
		"decided_at": timestamp(),
	}, "request_id", "approver_subject", "decision", "decision_evidence_refs", "decided_at")
	accessChangeRequest := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(),
		"requested_action":  {Type: "string", Enum: []string{"grant", "modify", "revoke", "rotate", "deploy", "break_glass"}},
		"requester_subject": str(), "nhi_id": str(), "nhi_kind": str(), "display_name": str(),
		"owner_ref": str(), "resource": str(), "entitlement": str(), "change_ref": str(),
		"change_system": str(), "change_url": str(), "risk": str(), "reason": str(),
		"evidence_refs":      {Type: "array", Items: str()},
		"status":             {Type: "string", Enum: []string{"pending", "approved", "denied"}},
		"required_approvals": {Type: "integer"},
		"approval_count":     {Type: "integer"},
		"created_at":         timestamp(),
		"updated_at":         timestamp(),
		"completed_at":       timestamp(),
		"decisions":          {Type: "array", Items: ref("AccessChangeDecision")},
	}, "id", "tenant_id", "requested_action", "requester_subject", "nhi_id", "nhi_kind", "display_name", "resource", "entitlement", "change_ref", "change_system", "risk", "reason", "evidence_refs", "status", "required_approvals", "approval_count", "created_at", "updated_at")

	certificate := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "owner_id": uuid(), "subject": str(),
		"identity_ids": {Type: "array", Items: uuid(), Description: "Managing identities proved by retained issuance or successful delivery evidence. Returned by certificate inventory list/detail reads. Absent means no resolved binding; multiple values require explicit selection. Never inferred from a name or owner."},
		"sans":         {Type: "array", Items: str()}, "issuer": str(), "serial": str(),
		"fingerprint": str(), "key_algorithm": str(), "not_before": timestamp(), "not_after": timestamp(),
		"deployment_location": str(), "source": str(), "created_at": timestamp(),
		"status":            {Type: "string", Enum: []string{"active", "superseded", "revoked"}},
		"revoked_at":        timestamp(),
		"revocation_reason": str(),
		// B5: per-certificate key custody. Empty means UNRECORDED, which is a
		// distinct answer from any observation.
		"key_origin":       {Type: "string", Enum: []string{"", "requester", "host_agent", "device", "control_plane", "signer"}},
		"key_storage":      {Type: "string", Enum: []string{"", "locked_memory", "sealed_store", "file", "os_store", "pkcs11", "device_bound", "service"}},
		"key_exportable":   {Type: "string", Enum: []string{"", "exportable", "non_exportable"}},
		"key_generated_by": str(),
		"custody_summary":  str(),
	}, "id", "tenant_id", "subject", "fingerprint", "status")
	identityIssuanceResult := object(map[string]*Schema{
		"identity_id": uuid(), "request_key": str(),
		"state":       {Type: "string", Enum: []string{"pending", "issued", "failed", "unavailable"}},
		"certificate": ref("Certificate"), "certificate_pem": str(),
		"retry": object(map[string]*Schema{"allowed": {Type: "boolean"}, "reason": str()}, "allowed", "reason"),
		"delivery": object(map[string]*Schema{
			"status":   {Type: "string", Enum: []string{"pending", "processing", "delivered", "failed"}},
			"attempts": {Type: "integer"},
		}, "status", "attempts"),
	}, "identity_id", "request_key", "state")
	identityIssuanceResult.Description = "Exact accepted issuance and its recorded public certificate. Failed means the original receiver command exhausted delivery and will not retry automatically; it does not prove no upstream certificate was signed. Unavailable means neither a recorded leaf nor its delivery bookkeeping is retained. Pending also covers delivery handed to an asynchronous host agent. A recorded certificate takes precedence over receiver status; it is not proof of deployment or listener verification. Reads never retry issuance."
	identityDeploymentEvidence := object(map[string]*Schema{
		"identity_id": uuid(), "read_at": timestamp(),
		"receipt": ref("ConnectorDelivery"), "certificate": ref("Certificate"),
	}, "identity_id", "read_at")
	firstIssuanceRetryRequest := object(map[string]*Schema{"request_key": str(), "reason": str()}, "request_key", "reason")
	firstIssuanceRetry := object(map[string]*Schema{
		"identity_id": uuid(), "request_key": str(), "retry_event_id": str(),
		"state":    {Type: "string", Enum: []string{"pending"}},
		"attempts": {Type: "integer"}, "attempt_grant": {Type: "integer"},
	}, "identity_id", "request_key", "retry_event_id", "state", "attempts", "attempt_grant")
	firstIssuanceRetry.Description = "One audited additional attempt for the original failed ca.issue command. Attempts is its cumulative count before this grant, which always permits one additional claim. The original command, issuer binding and idempotency key are preserved. Retained source replay never refunds a consumed grant. Historical requests without a recorded certificate or recoverable signing operation require issuer reconciliation."
	identityDeploymentEvidence.Description = "Last completed deployment or rollback for this exact tenant and identity, ordered by receipt update time and ID. Historical evidence, not a fresh listener probe or a claim about other destinations. A later replacement may serve another certificate. No receipt means no retained completion; a receipt without certificate means inventory metadata is unavailable. Revoked and superseded certificate status is preserved."
	certificateIngest := object(map[string]*Schema{
		"pem": str(), "owner_id": uuid(), "deployment_location": str(), "source": str(),
	}, "pem")
	certificateHealthSummary := object(map[string]*Schema{
		"total":                 {Type: "integer"},
		"active":                {Type: "integer"},
		"revoked":               {Type: "integer"},
		"superseded":            {Type: "integer"},
		"expired":               {Type: "integer"},
		"expiring_7d":           {Type: "integer"},
		"expiring_30d":          {Type: "integer"},
		"expiring_90d":          {Type: "integer"},
		"expiring_180d":         {Type: "integer"},
		"expiring_1y":           {Type: "integer"},
		"expiring_2y":           {Type: "integer"},
		"expiring_3y":           {Type: "integer"},
		"external_source_count": {Type: "integer"},
		"imported_count":        {Type: "integer"},
		"discovered_count":      {Type: "integer"},
		"unknown_expiry_count":  {Type: "integer"},
		"health":                {Type: "string", Enum: []string{"ok", "warning", "critical"}},
	}, "total", "active", "revoked", "superseded", "expired", "expiring_7d", "expiring_30d", "expiring_90d", "external_source_count", "imported_count", "discovered_count", "unknown_expiry_count", "health")
	certificateExpiryBucket := object(map[string]*Schema{
		// Long-horizon bands (H5). "later" keeps its name and its place at the end
		// of the partition but now means "beyond three years"; the 90-day ceiling
		// is what hid multi-year CA expiry.
		"name": {Type: "string", Enum: []string{
			"expired", "expiring_7d", "expiring_30d", "expiring_90d",
			"expiring_180d", "expiring_1y", "expiring_2y", "expiring_3y",
			"later", "unknown",
		}},
		"count": {Type: "integer"},
	}, "name", "count")
	certificateSourceHealth := object(map[string]*Schema{
		"source":       str(),
		"count":        {Type: "integer"},
		"external":     {Type: "boolean"},
		"expired":      {Type: "integer"},
		"expiring_30d": {Type: "integer"},
	}, "source", "count", "external", "expired", "expiring_30d")
	certificateHealthItem := object(map[string]*Schema{
		"id": uuid(), "subject": str(), "fingerprint": str(), "deployment_location": str(), "source": str(),
		"status":            {Type: "string", Enum: []string{"active", "superseded", "revoked"}},
		"not_after":         timestamp(),
		"days_remaining":    {Type: "integer"},
		"externally_issued": {Type: "boolean"},
	}, "id", "subject", "fingerprint", "source", "status", "days_remaining", "externally_issued")
	certificateHealthDashboard := object(map[string]*Schema{
		"generated_at":     timestamp(),
		"inventory_path":   str(),
		"expiring_path":    str(),
		"summary":          ref("CertificateHealthSummary"),
		"expiry_buckets":   {Type: "array", Items: ref("CertificateExpiryBucket")},
		"source_breakdown": {Type: "array", Items: ref("CertificateSourceHealth")},
		"expiring":         {Type: "array", Items: ref("CertificateHealthItem")},
	}, "generated_at", "inventory_path", "expiring_path", "summary", "expiry_buckets", "source_breakdown", "expiring")
	rogueCertificateSummary := object(map[string]*Schema{
		"total_analyzed":      {Type: "integer"},
		"findings":            {Type: "integer"},
		"rogue":               {Type: "integer"},
		"non_compliant":       {Type: "integer"},
		"ct_unexpected":       {Type: "integer"},
		"weak_key":            {Type: "integer"},
		"lifetime_violations": {Type: "integer"},
		"expired_active":      {Type: "integer"},
		"owner_missing":       {Type: "integer"},
		"issuer_missing":      {Type: "integer"},
		"critical":            {Type: "integer"},
		"high":                {Type: "integer"},
		"medium":              {Type: "integer"},
		"low":                 {Type: "integer"},
		"recommendations":     {Type: "integer"},
	}, "total_analyzed", "findings", "rogue", "non_compliant", "ct_unexpected", "weak_key", "lifetime_violations", "expired_active", "owner_missing", "issuer_missing", "critical", "high", "medium", "low", "recommendations")
	rogueCertificateFinding := object(map[string]*Schema{
		"id":              str(),
		"certificate_id":  uuid(),
		"discovery_id":    uuid(),
		"source_id":       uuid(),
		"run_id":          uuid(),
		"kind":            {Type: "string", Enum: []string{"rogue_certificate", "non_compliant_certificate"}},
		"policy_status":   {Type: "string", Enum: []string{"rogue", "non_compliant"}},
		"subject":         str(),
		"issuer":          str(),
		"serial":          str(),
		"fingerprint":     str(),
		"dns_names":       {Type: "array", Items: str()},
		"source":          str(),
		"owner_id":        uuid(),
		"status":          str(),
		"finding_types":   {Type: "array", Items: str()},
		"severity":        {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":      {Type: "integer"},
		"lifetime_days":   {Type: "integer"},
		"policy_max_days": {Type: "integer"},
		"log_url":         str(),
		"log_index":       {Type: "integer"},
		"matched_domain":  str(),
		"recommendation":  str(),
		"evidence_refs":   {Type: "array", Items: str()},
		"discovered_at":   timestamp(),
		"not_before":      timestamp(),
		"not_after":       timestamp(),
	}, "id", "kind", "policy_status", "subject", "source", "finding_types", "severity", "risk_score", "recommendation", "evidence_refs")
	rogueCertificatePosture := object(map[string]*Schema{
		"capability":          str(),
		"generated_at":        timestamp(),
		"coverage":            {Type: "array", Items: str()},
		"summary":             ref("RogueCertificateSummary"),
		"findings":            {Type: "array", Items: ref("RogueCertificateFinding")},
		"recommended_actions": {Type: "array", Items: str()},
		"evidence_refs":       {Type: "array", Items: str()},
	}, "capability", "generated_at", "coverage", "summary", "findings", "recommended_actions", "evidence_refs")
	crlDistributionShard := object(map[string]*Schema{
		"index":         {Type: "integer"},
		"url":           str(),
		"revoked_count": {Type: "integer"},
	}, "index", "url", "revoked_count")
	crlDistribution := object(map[string]*Schema{
		"tenant_id":         uuid(),
		"ca_id":             uuid(),
		"full_url":          str(),
		"full_number":       {Type: "integer"},
		"shard_count":       {Type: "integer"},
		"shards":            {Type: "array", Items: ref("CRLDistributionShard")},
		"delta_url":         str(),
		"delta_base_number": {Type: "integer"},
		"this_update":       timestamp(),
		"next_update":       timestamp(),
		"revoked_count":     {Type: "integer"},
	}, "tenant_id", "ca_id", "full_url", "full_number", "shard_count", "shards", "this_update", "next_update", "revoked_count")
	ctLogSubmissionReq := object(map[string]*Schema{
		"certificate_pem":          str(),
		"precertificate_pem":       str(),
		"chain_pem":                {Type: "array", Items: str()},
		"logs":                     {Type: "array", Items: str()},
		"allow_private_endpoint":   {Type: "boolean"},
		"private_egress_cidrs":     {Type: "array", Items: str()},
		"submission_profile":       str(),
		"operator_correlation_ref": str(),
	}, "certificate_pem", "logs")
	ctLogSubmissionLog := object(map[string]*Schema{
		"log_url":                      str(),
		"precertificate_queued":        {Type: "boolean"},
		"certificate_queued":           {Type: "boolean"},
		"precertificate_submission_id": uuid(),
		"certificate_submission_id":    uuid(),
	}, "log_url", "precertificate_queued", "certificate_queued")
	ctLogSubmissionNote := object(map[string]*Schema{
		"code":   str(),
		"detail": str(),
	}, "code", "detail")
	ctLogSubmission := object(map[string]*Schema{
		"capability": str(),
		"queued":     {Type: "integer"},
		"logs":       {Type: "array", Items: ref("CTLogSubmissionLog")},
		"residuals":  {Type: "array", Items: ref("CTLogSubmissionNote")},
	}, "capability", "queued", "logs")

	discoverySourceKinds := sourcecatalog.Kinds()
	discoverySource := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: discoverySourceKinds},
		"name": str(), "config": {Type: "object"}, "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "kind", "name", "config", "created_at", "updated_at")
	discoverySourceReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: discoverySourceKinds}, "name": str(), "config": {Type: "object"},
	}, "kind", "name")
	discoveryCapabilityField := object(map[string]*Schema{
		"path": str(), "label": str(), "type": str(), "required": {Type: "boolean"},
		"secret_ref": {Type: "boolean"}, "advanced": {Type: "boolean"}, "description": str(),
	}, "path", "label", "type", "required", "description")
	discoveryCapabilityProvider := object(map[string]*Schema{
		"id": str(), "label": str(), "least_privilege": str(), "preferred_credential": str(),
		"fields": {Type: "array", Items: str()},
	}, "id", "label", "least_privilege", "preferred_credential", "fields")
	discoveryCapability := object(map[string]*Schema{
		"kind": {Type: "string", Enum: discoverySourceKinds}, "label": str(), "purpose": str(), "data_handling": str(),
		"tool": str(), "route": str(), "setup_surface": {Type: "string", Enum: []string{"source_wizard", "contextual"}},
		"permission": str(), "edition": str(), "execution": str(),
		"configuration": {Type: "array", Items: ref("DiscoveryCapabilityField")},
		"providers":     {Type: "array", Items: ref("DiscoveryCapabilityProvider")},
		"lifecycle":     {Type: "array", Items: str()}, "console_stages": {Type: "array", Items: str()}, "documentation_ref": str(),
	}, "kind", "label", "purpose", "data_handling", "tool", "route", "setup_surface", "permission", "edition", "execution", "configuration", "lifecycle", "console_stages", "documentation_ref")
	discoveryCapabilityCatalog := object(map[string]*Schema{
		"schema_version": {Type: "integer"}, "items": {Type: "array", Items: ref("DiscoveryCapability")},
	}, "schema_version", "items")
	discoveryPlanPreview := object(map[string]*Schema{
		"kind": {Type: "string", Enum: discoverySourceKinds}, "ready": {Type: "boolean"}, "execution": str(), "protocol": str(),
		"connection_origin": str(), "segment": str(),
		"normalized_targets": {Type: "array", Items: str()}, "normalized_target_count": {Type: "integer"},
		"preview_truncated": {Type: "boolean"}, "excluded_target_count": {Type: "integer"},
		"applied_exclusions": {Type: "array", Items: str()}, "child_job_count": {Type: "integer"},
		"concurrency": {Type: "integer"}, "queue_depth": {Type: "integer"}, "estimated_upper_seconds": {Type: "integer"},
		"permission": str(), "data_handling": str(), "side_effects": {Type: "boolean"},
		"blocked_reasons": {Type: "array", Items: str()},
	}, "kind", "execution", "connection_origin", "normalized_target_count", "preview_truncated", "excluded_target_count", "child_job_count", "concurrency", "queue_depth", "estimated_upper_seconds", "permission", "data_handling", "side_effects", "blocked_reasons")
	discoverySegmentReq := object(map[string]*Schema{
		"name": str(), "ranges": {Type: "array", Items: str()},
		"staleness_hours": {Type: "integer"}, "excluded": {Type: "boolean"},
		"exclusion_reason": str(),
	}, "name", "ranges")
	discoverySegment := object(map[string]*Schema{
		"id": uuid(), "name": str(), "ranges": {Type: "array", Items: str()},
		"staleness_hours": {Type: "integer"}, "excluded": {Type: "boolean"},
		"exclusion_reason": str(), "last_swept_at": timestamp(), "last_swept_by": str(),
		"last_found_count": {Type: "integer"}, "created_at": timestamp(),
	}, "id", "name", "ranges", "staleness_hours", "excluded", "last_found_count", "created_at")
	discoverySchedule := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "source_id": uuid(), "name": str(),
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		"created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "source_id", "name", "interval_seconds", "enabled")
	discoveryScheduleReq := object(map[string]*Schema{
		"source_id": uuid(), "name": str(), "interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
	}, "source_id", "name", "interval_seconds")
	discoveryRun := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "source_id": uuid(), "schedule_id": uuid(),
		"retry_of_run_id": uuid(),
		"status":          {Type: "string", Enum: []string{"queued", "running", "succeeded", "partial", "failed"}},
		"dry_run":         {Type: "boolean"}, "requested_by": str(),
		"execution": {Type: "string", Enum: []string{"control_plane", "relay"}},
		"segment":   str(), "required_agent_role": str(), "required_agent_id": uuid(), "executed_by_agent_id": uuid(),
		"targets": {Type: "integer"}, "discovered": {Type: "integer"}, "failed": {Type: "integer"},
		"rejected": {Type: "integer"}, "blocked": {Type: "integer"}, "error": str(), "started_at": timestamp(),
		"completed_at": timestamp(), "created_at": timestamp(),
		"target_results": {Type: "array", Items: object(map[string]*Schema{
			"kind":   {Type: "string", Enum: []string{"network", "ssh", "cloud_provider"}},
			"target": str(),
			"status": {Type: "string", Enum: []string{"succeeded", "failed", "blocked", "rejected"}},
			"error":  str(),
		}, "kind", "target", "status")},
	}, "id", "tenant_id", "source_id", "status", "dry_run", "execution", "targets", "discovered", "failed", "rejected", "blocked", "created_at", "target_results")
	discoveryRunReq := object(map[string]*Schema{
		"source_id": uuid(), "schedule_id": uuid(), "dry_run": {Type: "boolean"},
	}, "source_id")
	discoveryFinding := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "run_id": uuid(), "source_id": uuid(),
		"kind": str(), "ref": str(), "provenance": str(), "fingerprint": str(),
		"risk_score": {Type: "integer"}, "metadata": {Type: "object"}, "discovered_at": timestamp(),
		"triage_status":       {Type: "string", Enum: []string{"unmanaged", "investigating", "managed", "dismissed"}},
		"managed_identity_id": uuid(), "triage_actor": str(), "triage_reason": str(), "triaged_at": timestamp(),
		"first_seen_at": timestamp(), "last_seen_at": timestamp(), "seen_count": {Type: "integer"},
	}, "id", "tenant_id", "run_id", "source_id", "kind", "ref", "provenance", "fingerprint", "metadata", "discovered_at", "first_seen_at", "last_seen_at", "seen_count")
	discoveryFindingTriageReq := object(map[string]*Schema{
		"managed_identity_id": uuid(), "reason": str(), "owner": str(), "team": str(),
		"tags": {Type: "array", Items: str()},
	})
	discoveryMonitoringSummary := object(map[string]*Schema{
		"source_count":                {Type: "integer"},
		"scheduled_source_count":      {Type: "integer"},
		"active_monitoring_count":     {Type: "integer"},
		"run_count":                   {Type: "integer"},
		"completed_run_count":         {Type: "integer"},
		"failed_run_count":            {Type: "integer"},
		"finding_count":               {Type: "integer"},
		"open_finding_count":          {Type: "integer"},
		"certificate_inventory_count": {Type: "integer"},
	}, "source_count", "scheduled_source_count", "active_monitoring_count", "run_count", "completed_run_count", "failed_run_count", "finding_count", "open_finding_count", "certificate_inventory_count")
	discoveryMonitoringSource := object(map[string]*Schema{
		"source_id":                   uuid(),
		"kind":                        {Type: "string", Enum: discoverySourceKinds},
		"name":                        str(),
		"execution_ready":             {Type: "boolean"},
		"connection_origin":           str(),
		"blocked_reasons":             {Type: "array", Items: str()},
		"scheduled":                   {Type: "boolean"},
		"schedule_id":                 str(),
		"monitoring_interval_seconds": {Type: "integer"},
		"last_run_id":                 str(),
		"last_run_status":             str(),
		"last_run_error":              str(),
		"last_run_completed_at":       timestamp(),
		"last_discovery_at":           timestamp(),
		"run_count":                   {Type: "integer"},
		"completed_run_count":         {Type: "integer"},
		"failed_run_count":            {Type: "integer"},
		"finding_count":               {Type: "integer"},
		"open_finding_count":          {Type: "integer"},
		"certificate_inventory_count": {Type: "integer"},
		"repository_path":             str(),
		"findings_path":               str(),
		"updated_at":                  timestamp(),
	}, "source_id", "kind", "name", "scheduled", "schedule_id", "monitoring_interval_seconds", "last_run_id", "last_run_status", "last_run_error", "run_count", "completed_run_count", "failed_run_count", "finding_count", "open_finding_count", "certificate_inventory_count", "repository_path", "findings_path", "updated_at")
	discoveryMonitoring := object(map[string]*Schema{
		"repository_path": str(),
		"findings_path":   str(),
		"sources_path":    str(),
		"schedules_path":  str(),
		"runs_path":       str(),
		"summary":         ref("DiscoveryMonitoringSummary"),
		"sources":         {Type: "array", Items: ref("DiscoveryMonitoringSource")},
	}, "repository_path", "findings_path", "sources_path", "schedules_path", "runs_path", "summary", "sources")
	discoveryCoverageClass := object(map[string]*Schema{
		"class":            str(),
		"status":           str(),
		"source_kinds":     {Type: "array", Items: str()},
		"observed_by":      {Type: "array", Items: str()},
		"last_observed_at": timestamp(),
		"reason":           str(),
		"action":           str(),
	}, "class", "status")
	// C3: coverage measured against DECLARED segments, plus inventory
	// provenance and the register of named blind spots.
	discoverySegmentCoverage := object(map[string]*Schema{
		"name":             str(),
		"ranges":           {Type: "array", Items: str()},
		"status":           {Type: "string", Enum: []string{"swept", "stale", "never", "excluded"}},
		"staleness_hours":  {Type: "integer"},
		"last_swept_at":    timestamp(),
		"last_swept_by":    str(),
		"last_found_count": {Type: "integer"},
		"exclusion_reason": str(),
	}, "name", "ranges", "status", "staleness_hours")
	discoveryProvenanceSummary := object(map[string]*Schema{
		"total":             {Type: "integer"},
		"observed":          {Type: "integer"},
		"stale":             {Type: "integer"},
		"never_observed":    {Type: "integer"},
		"stale_after_hours": {Type: "integer"},
	}, "total", "observed", "stale", "never_observed", "stale_after_hours")
	discoveryUnknown := object(map[string]*Schema{
		"kind": {Type: "string", Enum: []string{
			"segment_never_swept", "segment_stale", "segment_excluded",
			"segment_read_failed", "class_unobservable", "inventory_unobserved",
		}},
		"subject": str(),
		"detail":  str(),
		"action":  str(),
	}, "kind", "subject", "detail")
	// B7: when each upstream identifier last actually proved control, as
	// against when it last rode a reuse the install did not earn.
	acmeUpstreamAuthorization := object(map[string]*Schema{
		"identifier": str(), "issuer": str(), "challenge_type": str(),
		"last_validated_at": timestamp(), "last_reused_at": timestamp(),
		"expires_at":      timestamp(),
		"reuse_count":     {Type: "integer"},
		"validate_count":  {Type: "integer"},
		"never_validated": {Type: "boolean"},
	}, "identifier", "issuer", "reuse_count", "validate_count", "never_validated")
	acmeUpstreamAuthorizationList := object(map[string]*Schema{
		"items":                 {Type: "array", Items: ref("ACMEUpstreamAuthorization")},
		"never_validated_count": {Type: "integer"},
		"guidance":              str(),
	}, "items", "never_validated_count", "guidance")
	// D6: renewal success SLO and error-budget burn.
	renewalSLO := object(map[string]*Schema{
		"window_days": {Type: "integer"}, "target_percent": {Type: "number"},
		"total": {Type: "integer"}, "succeeded": {Type: "integer"}, "failed": {Type: "integer"},
		"observed_percent": {Type: "number"}, "budget_remaining_percent": {Type: "number"},
		"breached": {Type: "boolean"}, "guidance": str(),
	}, "window_days", "target_percent", "total", "succeeded", "failed",
		"observed_percent", "budget_remaining_percent", "breached", "guidance")
	// D3: issued / delivered / verified, counted separately.
	deploymentTriState := object(map[string]*Schema{
		"delivered": {Type: "integer"}, "verified": {Type: "integer"},
		"verify_failed": {Type: "integer"}, "unverified": {Type: "integer"},
		"verified_percent": {Type: "integer"},
	}, "delivered", "verified", "verify_failed", "unverified", "verified_percent")
	// D2: what each listener is actually serving, per vantage.
	endpointVerification := object(map[string]*Schema{
		"endpoint_id": str(), "address": str(),
		"vantage": {Type: "string", Enum: []string{"local", "relay"}},
		"status":  {Type: "string", Enum: []string{"verified", "diverged", "unreachable", "not_checked"}},
		"mismatch": {Type: "string", Enum: []string{
			"fingerprint", "sans", "chain", "expired", "not_yet_valid",
		}},
		"checked_sans": {Type: "boolean"}, "checked_chain": {Type: "boolean"},
		"expected_fingerprint": str(), "observed_fingerprint": str(),
		"not_after": timestamp(), "detail": str(),
		"evidence_digest": str(), "agent_common_name": str(),
		"last_checked_at": timestamp(), "last_good_at": timestamp(),
		"stale_for_seconds": {Type: "integer"},
	}, "endpoint_id", "address", "vantage", "status", "checked_sans", "checked_chain")
	endpointVerificationSummary := object(map[string]*Schema{
		"endpoints": {Type: "integer"}, "verified": {Type: "integer"},
		"diverged": {Type: "integer"}, "unreachable": {Type: "integer"},
		"verified_percent": {Type: "integer"},
	}, "endpoints", "verified", "diverged", "unreachable", "verified_percent")
	endpointVerificationList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("EndpointVerification")},
		"summary":  ref("EndpointVerificationSummary"),
		"guidance": str(),
	}, "items", "summary", "guidance")
	// R1: signed CRL/OCSP endpoint evidence observed from a network relay.
	revocationEndpointHealth := object(map[string]*Schema{
		"target_key": str(), "protocol": {Type: "string", Enum: []string{"crl", "ocsp"}},
		"endpoint": str(), "issuer_subject": str(), "issuer_fingerprint": str(),
		"certificate_id": str(), "certificate_subject": str(), "certificate_fingerprint": str(),
		"certificate_serial": str(),
		"status":             {Type: "string", Enum: []string{"fresh", "expiring", "stale", "unreachable", "unparseable"}},
		"detail_code":        str(), "latency_ms": {Type: "integer"},
		"this_update": timestamp(), "next_update": timestamp(), "signature_verified": {Type: "boolean"},
		"revoked_count": {Type: "integer"}, "response_status": {Type: "string", Enum: []string{"good", "revoked", "unknown"}},
		"responder_subject": str(), "probe_id": str(), "observed_by_agent_id": str(),
		"observed_by_agent_name": str(), "evidence_digest": str(), "observed_at": timestamp(),
	}, "target_key", "protocol", "endpoint", "issuer_subject", "certificate_id", "certificate_subject",
		"certificate_fingerprint", "certificate_serial", "status", "detail_code", "latency_ms",
		"signature_verified", "probe_id", "observed_by_agent_id", "observed_by_agent_name", "evidence_digest", "observed_at")
	revocationHealthSummary := object(map[string]*Schema{
		"endpoints": {Type: "integer"}, "fresh": {Type: "integer"}, "expiring": {Type: "integer"},
		"stale": {Type: "integer"}, "unreachable": {Type: "integer"}, "unparseable": {Type: "integer"},
	}, "endpoints", "fresh", "expiring", "stale", "unreachable", "unparseable")
	revocationHealth := object(map[string]*Schema{
		"observed": {Type: "boolean"}, "items": {Type: "array", Items: ref("RevocationEndpointHealth")},
		"summary": ref("RevocationHealthSummary"), "guidance": str(),
	}, "observed", "items", "summary", "guidance")
	// R3: signed metadata-only relay-local cache posture.
	revocationCacheStatus := object(map[string]*Schema{
		"agent_id": str(), "agent_name": str(), "segment": str(), "cache_id": str(),
		"protocol":           {Type: "string", Enum: []string{"crl", "ocsp"}},
		"issuer_fingerprint": str(), "local_path": str(),
		"status":      {Type: "string", Enum: []string{"fresh", "stale", "empty", "error"}},
		"detail_code": str(), "cached_responses": {Type: "integer"}, "fresh": {Type: "boolean"},
		"signature_verified": {Type: "boolean"}, "metadata_only": {Type: "boolean"},
		"this_update": timestamp(), "next_update": timestamp(), "last_validated_at": timestamp(),
		"served_requests": {Type: "integer"}, "refused_requests": {Type: "integer"},
		"signer_fingerprint": str(), "reported_at": timestamp(),
	}, "agent_id", "agent_name", "segment", "cache_id", "protocol", "issuer_fingerprint", "local_path",
		"status", "cached_responses", "fresh", "signature_verified", "metadata_only", "served_requests",
		"refused_requests", "signer_fingerprint", "reported_at")
	revocationCacheSummary := object(map[string]*Schema{
		"caches": {Type: "integer"}, "fresh": {Type: "integer"}, "stale": {Type: "integer"},
		"empty": {Type: "integer"}, "error": {Type: "integer"},
	}, "caches", "fresh", "stale", "empty", "error")
	revocationCachePosture := object(map[string]*Schema{
		"observed": {Type: "boolean"}, "items": {Type: "array", Items: ref("RevocationCacheStatus")},
		"summary": ref("RevocationCacheSummary"), "guidance": str(),
	}, "observed", "items", "summary", "guidance")
	// B2: where each deployment target's private key is generated.
	endpointKeyCustody := object(map[string]*Schema{
		"target_id": str(), "name": str(), "connector": str(),
		"executor":                      {Type: "string", Enum: []string{"agent", "control_plane"}},
		"origin":                        {Type: "string", Enum: []string{"host_agent", "control_plane"}},
		"key_bytes_leave_control_plane": {Type: "boolean"},
		"enabled":                       {Type: "boolean"},
		"detail":                        str(),
		"last_executed_by_agent":        str(),
		"last_executed_at":              timestamp(),
		"last_executed_outcome":         str(),
	}, "target_id", "name", "connector", "executor", "origin",
		"key_bytes_leave_control_plane", "enabled", "detail")
	endpointCustodySummary := object(map[string]*Schema{
		"targets": {Type: "integer"}, "host_generated": {Type: "integer"},
		"control_plane_generated": {Type: "integer"}, "migrated_percent": {Type: "integer"},
	}, "targets", "host_generated", "control_plane_generated", "migrated_percent")
	endpointKeyCustodyList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("EndpointKeyCustody")},
		"summary":  ref("EndpointCustodySummary"),
		"guidance": str(),
	}, "items", "summary", "guidance")
	// R2: what each authority can actually do through trstctl.
	issuerCapability := object(map[string]*Schema{
		"issuer": str(), "discover": {Type: "boolean"}, "issue": {Type: "boolean"},
		"renew": {Type: "boolean"}, "revoke": {Type: "boolean"},
		"key_handling": {Type: "string", Enum: []string{"requester_csr", "authority_generated"}},
		"validation": {Type: "string", Enum: []string{
			"acme_challenge", "account_scoped", "organizational", "internal",
		}},
		"revoke_note": str(),
		// B7: can trstctl keep this authority validated with nobody in the loop.
		"unattended_dv":      {Type: "boolean"},
		"unattended_dv_note": str(),
		"issue_proven":       {Type: "boolean"},
		"evidence":           str(),
	}, "issuer", "discover", "issue", "renew", "revoke", "key_handling", "validation", "unattended_dv")
	issuerCapabilityMatrix := object(map[string]*Schema{
		"issuers":                     {Type: "array", Items: ref("IssuerCapability")},
		"revoke_capable_count":        {Type: "integer"},
		"unattended_dv_capable_count": {Type: "integer"},
		"guidance":                    str(),
	}, "issuers", "revoke_capable_count", "unattended_dv_capable_count", "guidance")
	discoveryCoverage := object(map[string]*Schema{
		"generated_at":              timestamp(),
		"observed":                  {Type: "integer"},
		"unobserved":                {Type: "integer"},
		"structurally_unobservable": {Type: "integer"},
		"classes":                   {Type: "array", Items: ref("DiscoveryCoverageClass")},
		"segments":                  {Type: "array", Items: ref("DiscoverySegmentCoverage")},
		"segment_coverage_percent":  {Type: "integer"},
		"provenance":                ref("DiscoveryProvenanceSummary"),
		"unknowns":                  {Type: "array", Items: ref("DiscoveryUnknown")},
	}, "generated_at", "observed", "unobserved", "structurally_unobservable", "classes",
		"segments", "segment_coverage_percent", "provenance", "unknowns")
	ctMonitoringReq := object(map[string]*Schema{
		"source_id":              uuid(),
		"name":                   str(),
		"logs":                   {Type: "array", Items: str()},
		"watched_domains":        {Type: "array", Items: str()},
		"max_batch":              {Type: "integer"},
		"run_now":                {Type: "boolean"},
		"dry_run":                {Type: "boolean"},
		"allow_private_endpoint": {Type: "boolean"},
		"private_egress_cidrs":   {Type: "array", Items: str()},
	}, "logs", "watched_domains")
	ctMonitoringLog := object(map[string]*Schema{
		"url":            str(),
		"next_index":     {Type: "integer"},
		"status":         {Type: "string", Enum: []string{"never", "succeeded", "failed"}},
		"last_error":     str(),
		"last_polled_at": timestamp(),
		"retired_at":     timestamp(),
	}, "url", "next_index", "status")
	ctMonitoringSummary := object(map[string]*Schema{
		"source_count":               {Type: "integer"},
		"watched_domain_count":       {Type: "integer"},
		"log_count":                  {Type: "integer"},
		"retired_log_count":          {Type: "integer"},
		"failed_log_count":           {Type: "integer"},
		"finding_count":              {Type: "integer"},
		"unexpected_issuance_count":  {Type: "integer"},
		"open_finding_count":         {Type: "integer"},
		"outbox_alert_channel_count": {Type: "integer"},
	}, "source_count", "watched_domain_count", "log_count", "retired_log_count", "failed_log_count", "finding_count", "unexpected_issuance_count", "open_finding_count", "outbox_alert_channel_count")
	ctMonitoring := object(map[string]*Schema{
		"capability":               str(),
		"watchlist_path":           str(),
		"sources_path":             str(),
		"runs_path":                str(),
		"findings_path":            str(),
		"notification_destination": str(),
		"outbox_backed_alerts":     {Type: "boolean"},
		"watched_domains":          {Type: "array", Items: str()},
		"logs":                     {Type: "array", Items: ref("CTMonitoringLog")},
		"retired_logs":             {Type: "array", Items: ref("CTMonitoringLog")},
		"summary":                  ref("CTMonitoringSummary"),
		"source":                   ref("DiscoverySource"),
		"run":                      ref("DiscoveryRun"),
		"findings":                 {Type: "array", Items: ref("DiscoveryFinding")},
	}, "capability", "watchlist_path", "sources_path", "runs_path", "findings_path", "notification_destination", "outbox_backed_alerts", "watched_domains", "logs", "retired_logs", "summary", "findings")
	driftRemediationDecisionReq := object(map[string]*Schema{
		"decision":            {Type: "string", Enum: []string{"investigate", "mark_managed", "dismiss"}},
		"managed_identity_id": uuid(),
		"reason":              str(),
		"owner":               str(),
		"team":                str(),
		"tags":                {Type: "array", Items: str()},
	}, "decision")
	driftRemediationSummary := object(map[string]*Schema{
		"source_count":               {Type: "integer"},
		"finding_count":              {Type: "integer"},
		"open_finding_count":         {Type: "integer"},
		"investigating_count":        {Type: "integer"},
		"remediated_count":           {Type: "integer"},
		"dismissed_count":            {Type: "integer"},
		"remediation_decision_count": {Type: "integer"},
		"deleted_count":              {Type: "integer"},
		"replaced_count":             {Type: "integer"},
		"relocated_count":            {Type: "integer"},
		"permission_changed_count":   {Type: "integer"},
		"certificate_count":          {Type: "integer"},
		"ssh_key_count":              {Type: "integer"},
		"secret_count":               {Type: "integer"},
	}, "source_count", "finding_count", "open_finding_count", "investigating_count", "remediated_count", "dismissed_count", "remediation_decision_count", "deleted_count", "replaced_count", "relocated_count", "permission_changed_count", "certificate_count", "ssh_key_count", "secret_count")
	driftRemediationFinding := object(map[string]*Schema{
		"finding_id":          uuid(),
		"run_id":              uuid(),
		"source_id":           uuid(),
		"source_name":         str(),
		"ref":                 str(),
		"provenance":          str(),
		"fingerprint":         str(),
		"risk_score":          {Type: "integer"},
		"drift_type":          {Type: "string", Enum: []string{"deleted", "replaced", "relocated", "permission_changed", "unknown"}},
		"credential_class":    str(),
		"expected_mode":       str(),
		"actual_mode":         str(),
		"triage_status":       {Type: "string", Enum: []string{"unmanaged", "investigating", "managed", "dismissed"}},
		"triage_actor":        str(),
		"triage_reason":       str(),
		"triaged_at":          timestamp(),
		"metadata":            {Type: "object"},
		"recommended_action":  str(),
		"available_decisions": {Type: "array", Items: str()},
		"evidence_refs":       {Type: "array", Items: str()},
	}, "finding_id", "run_id", "source_id", "source_name", "ref", "provenance", "fingerprint", "risk_score", "drift_type", "credential_class", "triage_status", "metadata", "recommended_action", "available_decisions", "evidence_refs")
	driftRemediation := object(map[string]*Schema{
		"capability":     str(),
		"dashboard_path": str(),
		"sources_path":   str(),
		"runs_path":      str(),
		"findings_path":  str(),
		"summary":        ref("DriftRemediationSummary"),
		"findings":       {Type: "array", Items: ref("DriftRemediationFinding")},
	}, "capability", "dashboard_path", "sources_path", "runs_path", "findings_path", "summary", "findings")
	driftRemediationDecision := object(map[string]*Schema{
		"decision":      str(),
		"evidence_refs": {Type: "array", Items: str()},
		"finding":       ref("DriftRemediationFinding"),
	}, "decision", "evidence_refs", "finding")
	nhiInventoryItem := object(map[string]*Schema{
		"id":            str(),
		"tenant_id":     uuid(),
		"kind":          str(),
		"source":        str(),
		"display_name":  str(),
		"owner_id":      uuid(),
		"status":        str(),
		"ref":           str(),
		"provenance":    str(),
		"fingerprint":   str(),
		"risk_score":    {Type: "integer"},
		"metadata":      {Type: "object"},
		"not_before":    timestamp(),
		"not_after":     timestamp(),
		"discovered_at": timestamp(),
		"created_at":    timestamp(),
	}, "id", "tenant_id", "kind", "source", "display_name", "status", "metadata", "created_at")
	nhiInventoryRecordSummary := object(map[string]*Schema{
		"counting_mode":             {Type: "string", Enum: []string{"durable_source_records_not_unique_credentials"}},
		"total_records":             {Type: "integer"},
		"managed_identity_records":  {Type: "integer"},
		"certificate_records":       {Type: "integer"},
		"api_token_records":         {Type: "integer"},
		"agent_records":             {Type: "integer"},
		"discovery_finding_records": {Type: "integer"},
	}, "counting_mode", "total_records", "managed_identity_records", "certificate_records", "api_token_records", "agent_records", "discovery_finding_records")
	nhiInventory := object(map[string]*Schema{
		"generated_at":   timestamp(),
		"items":          {Type: "array", Items: ref("NHIInventoryItem")},
		"summary":        {Type: "object"},
		"record_summary": ref("NHIInventoryRecordSummary"),
		"coverage":       {Type: "array", Items: str()},
	}, "generated_at", "items", "summary", "record_summary", "coverage")
	nhiShadowSummary := object(map[string]*Schema{
		"total_analyzed": {Type: "integer"},
		"findings":       {Type: "integer"},
		"unmanaged":      {Type: "integer"},
		"investigating":  {Type: "integer"},
		"unregistered":   {Type: "integer"},
		"ownerless":      {Type: "integer"},
		"critical":       {Type: "integer"},
		"high":           {Type: "integer"},
		"medium":         {Type: "integer"},
		"low":            {Type: "integer"},
		"kind_counts":    {Type: "object"},
		"surface_counts": {Type: "object"},
	}, "total_analyzed", "findings", "unmanaged", "investigating", "unregistered", "ownerless", "critical", "high", "medium", "low", "kind_counts", "surface_counts")
	nhiShadowFinding := object(map[string]*Schema{
		"finding_id":          uuid(),
		"source_id":           uuid(),
		"run_id":              uuid(),
		"kind":                str(),
		"ref":                 str(),
		"display_name":        str(),
		"surface":             str(),
		"system":              str(),
		"provenance":          str(),
		"fingerprint":         str(),
		"triage_status":       {Type: "string", Enum: []string{"unmanaged", "investigating"}},
		"managed_identity_id": uuid(),
		"owner_status":        {Type: "string", Enum: []string{"owned_metadata", "ownerless"}},
		"severity":            {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":          {Type: "integer"},
		"recommendation":      str(),
		"evidence_refs":       {Type: "array", Items: str()},
		"discovered_at":       timestamp(),
	}, "finding_id", "source_id", "run_id", "kind", "ref", "display_name", "provenance", "triage_status", "owner_status", "severity", "risk_score", "recommendation", "evidence_refs", "discovered_at")
	nhiShadowPosture := object(map[string]*Schema{
		"capability":          str(),
		"generated_at":        timestamp(),
		"coverage":            {Type: "array", Items: str()},
		"summary":             ref("NHIShadowSummary"),
		"findings":            {Type: "array", Items: ref("NHIShadowFinding")},
		"recommended_actions": {Type: "array", Items: str()},
		"evidence_refs":       {Type: "array", Items: str()},
	}, "capability", "generated_at", "coverage", "summary", "findings", "recommended_actions", "evidence_refs")
	nhiPolicyComplianceSummary := object(map[string]*Schema{
		"total_analyzed":           {Type: "integer"},
		"compliant":                {Type: "integer"},
		"violations":               {Type: "integer"},
		"rotation_violations":      {Type: "integer"},
		"scope_violations":         {Type: "integer"},
		"geo_violations":           {Type: "integer"},
		"expiry_violations":        {Type: "integer"},
		"business_purpose_missing": {Type: "integer"},
		"critical":                 {Type: "integer"},
		"high":                     {Type: "integer"},
		"medium":                   {Type: "integer"},
		"low":                      {Type: "integer"},
	}, "total_analyzed", "compliant", "violations", "rotation_violations", "scope_violations", "geo_violations", "expiry_violations", "business_purpose_missing", "critical", "high", "medium", "low")
	nhiPolicyComplianceFinding := object(map[string]*Schema{
		"inventory_id":          str(),
		"kind":                  str(),
		"source":                str(),
		"display_name":          str(),
		"owner_id":              uuid(),
		"status":                str(),
		"policy_status":         {Type: "string", Enum: []string{"compliant", "violating"}},
		"severity":              {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":            {Type: "integer"},
		"violation_types":       {Type: "array", Items: str()},
		"rotation_cadence_days": {Type: "integer"},
		"credential_age_days":   {Type: "integer"},
		"max_ttl_days":          {Type: "integer"},
		"remaining_ttl_days":    {Type: "integer"},
		"allowed_scopes":        {Type: "array", Items: str()},
		"granted_scopes":        {Type: "array", Items: str()},
		"disallowed_scopes":     {Type: "array", Items: str()},
		"allowed_geos":          {Type: "array", Items: str()},
		"observed_geos":         {Type: "array", Items: str()},
		"disallowed_geos":       {Type: "array", Items: str()},
		"business_purpose":      str(),
		"recommendation":        str(),
		"evidence_refs":         {Type: "array", Items: str()},
		"last_rotated_at":       timestamp(),
		"expires_at":            timestamp(),
	}, "inventory_id", "kind", "source", "display_name", "status", "policy_status", "severity", "risk_score", "violation_types", "recommendation", "evidence_refs")
	nhiPolicyCompliance := object(map[string]*Schema{
		"capability":          str(),
		"generated_at":        timestamp(),
		"coverage":            {Type: "array", Items: str()},
		"summary":             ref("NHIPolicyComplianceSummary"),
		"findings":            {Type: "array", Items: ref("NHIPolicyComplianceFinding")},
		"recommended_actions": {Type: "array", Items: str()},
		"evidence_refs":       {Type: "array", Items: str()},
	}, "capability", "generated_at", "coverage", "summary", "findings", "recommended_actions", "evidence_refs")
	nhiOverPrivilegeSummary := object(map[string]*Schema{
		"total_analyzed":        {Type: "integer"},
		"overprivileged":        {Type: "integer"},
		"critical":              {Type: "integer"},
		"high":                  {Type: "integer"},
		"medium":                {Type: "integer"},
		"low":                   {Type: "integer"},
		"least_privilege_plans": {Type: "integer"},
		"unused_grants":         {Type: "integer"},
		"wildcard_grants":       {Type: "integer"},
	}, "total_analyzed", "overprivileged", "critical", "high", "medium", "low", "least_privilege_plans", "unused_grants", "wildcard_grants")
	nhiOverPrivilegeFinding := object(map[string]*Schema{
		"inventory_id":       str(),
		"ref":                str(),
		"kind":               str(),
		"source":             str(),
		"display_name":       str(),
		"owner_id":           uuid(),
		"status":             str(),
		"severity":           {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":         {Type: "integer"},
		"finding_types":      {Type: "array", Items: str()},
		"granted_scopes":     {Type: "array", Items: str()},
		"used_scopes":        {Type: "array", Items: str()},
		"unused_scopes":      {Type: "array", Items: str()},
		"recommended_scopes": {Type: "array", Items: str()},
		"unused_ratio":       {Type: "number"},
		"recommendation":     str(),
		"evidence_refs":      {Type: "array", Items: str()},
		"last_used_at":       timestamp(),
	}, "inventory_id", "kind", "source", "display_name", "status", "severity", "risk_score", "finding_types", "granted_scopes", "used_scopes", "unused_scopes", "recommended_scopes", "unused_ratio", "recommendation", "evidence_refs")
	nhiOverPrivilegePosture := object(map[string]*Schema{
		"capability":   str(),
		"generated_at": timestamp(),
		"coverage":     {Type: "array", Items: str()},
		"summary":      ref("NHIOverPrivilegeSummary"),
		"findings":     {Type: "array", Items: ref("NHIOverPrivilegeFinding")},
	}, "capability", "generated_at", "coverage", "summary", "findings")
	nhiStaleThresholds := object(map[string]*Schema{
		"stale_activity_days":     {Type: "integer"},
		"dormant_activity_days":   {Type: "integer"},
		"unused_no_activity_days": {Type: "integer"},
	}, "stale_activity_days", "dormant_activity_days", "unused_no_activity_days")
	nhiStaleSummary := object(map[string]*Schema{
		"total_analyzed":  {Type: "integer"},
		"findings":        {Type: "integer"},
		"stale":           {Type: "integer"},
		"dormant":         {Type: "integer"},
		"unused":          {Type: "integer"},
		"orphaned":        {Type: "integer"},
		"critical":        {Type: "integer"},
		"high":            {Type: "integer"},
		"medium":          {Type: "integer"},
		"low":             {Type: "integer"},
		"recommendations": {Type: "integer"},
	}, "total_analyzed", "findings", "stale", "dormant", "unused", "orphaned", "critical", "high", "medium", "low", "recommendations")
	nhiStaleFinding := object(map[string]*Schema{
		"inventory_id":      str(),
		"ref":               str(),
		"kind":              str(),
		"source":            str(),
		"display_name":      str(),
		"owner_id":          uuid(),
		"owner_status":      {Type: "string", Enum: []string{"owned", "subject_bound", "orphaned"}},
		"status":            str(),
		"severity":          {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":        {Type: "integer"},
		"finding_types":     {Type: "array", Items: str()},
		"activity_age_days": {Type: "integer"},
		"created_age_days":  {Type: "integer"},
		"last_activity_at":  timestamp(),
		"last_seen_at":      timestamp(),
		"last_used_at":      timestamp(),
		"created_at":        timestamp(),
		"recommendation":    str(),
		"evidence_refs":     {Type: "array", Items: str()},
	}, "inventory_id", "kind", "source", "display_name", "owner_status", "status", "severity", "risk_score", "finding_types", "activity_age_days", "created_age_days", "created_at", "recommendation", "evidence_refs")
	nhiStalePosture := object(map[string]*Schema{
		"capability":   str(),
		"generated_at": timestamp(),
		"coverage":     {Type: "array", Items: str()},
		"thresholds":   ref("NHIStaleThresholds"),
		"summary":      ref("NHIStaleSummary"),
		"findings":     {Type: "array", Items: ref("NHIStaleFinding")},
	}, "capability", "generated_at", "coverage", "thresholds", "summary", "findings")
	nhiStaticThresholds := object(map[string]*Schema{
		"long_lived_credential_days": {Type: "integer"},
		"rotation_overdue_days":      {Type: "integer"},
		"no_expiry_minimum_age_days": {Type: "integer"},
	}, "long_lived_credential_days", "rotation_overdue_days", "no_expiry_minimum_age_days")
	nhiStaticSummary := object(map[string]*Schema{
		"total_analyzed":     {Type: "integer"},
		"findings":           {Type: "integer"},
		"long_lived":         {Type: "integer"},
		"static_credentials": {Type: "integer"},
		"no_expiry":          {Type: "integer"},
		"rotation_overdue":   {Type: "integer"},
		"critical":           {Type: "integer"},
		"high":               {Type: "integer"},
		"medium":             {Type: "integer"},
		"low":                {Type: "integer"},
		"recommendations":    {Type: "integer"},
	}, "total_analyzed", "findings", "long_lived", "static_credentials", "no_expiry", "rotation_overdue", "critical", "high", "medium", "low", "recommendations")
	nhiStaticFinding := object(map[string]*Schema{
		"inventory_id":        str(),
		"ref":                 str(),
		"kind":                str(),
		"source":              str(),
		"display_name":        str(),
		"owner_id":            uuid(),
		"owner_status":        {Type: "string", Enum: []string{"owned", "subject_bound", "orphaned"}},
		"status":              str(),
		"severity":            {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":          {Type: "integer"},
		"finding_types":       {Type: "array", Items: str()},
		"credential_age_days": {Type: "integer"},
		"ttl_days":            {Type: "integer"},
		"rotation_age_days":   {Type: "integer"},
		"created_at":          timestamp(),
		"expires_at":          timestamp(),
		"last_rotated_at":     timestamp(),
		"recommendation":      str(),
		"evidence_refs":       {Type: "array", Items: str()},
	}, "inventory_id", "kind", "source", "display_name", "owner_status", "status", "severity", "risk_score", "finding_types", "credential_age_days", "ttl_days", "rotation_age_days", "created_at", "recommendation", "evidence_refs")
	nhiStaticPosture := object(map[string]*Schema{
		"capability":   str(),
		"generated_at": timestamp(),
		"coverage":     {Type: "array", Items: str()},
		"thresholds":   ref("NHIStaticThresholds"),
		"summary":      ref("NHIStaticSummary"),
		"findings":     {Type: "array", Items: ref("NHIStaticFinding")},
	}, "capability", "generated_at", "coverage", "thresholds", "summary", "findings")
	nhiExposureSummary := object(map[string]*Schema{
		"total_analyzed":         {Type: "integer"},
		"findings":               {Type: "integer"},
		"internet_exposed":       {Type: "integer"},
		"insecure_transport":     {Type: "integer"},
		"weak_authentication":    {Type: "integer"},
		"public_callbacks":       {Type: "integer"},
		"missing_network_policy": {Type: "integer"},
		"wildcard_reachability":  {Type: "integer"},
		"critical":               {Type: "integer"},
		"high":                   {Type: "integer"},
		"medium":                 {Type: "integer"},
		"low":                    {Type: "integer"},
		"recommendations":        {Type: "integer"},
	}, "total_analyzed", "findings", "internet_exposed", "insecure_transport", "weak_authentication", "public_callbacks", "missing_network_policy", "wildcard_reachability", "critical", "high", "medium", "low", "recommendations")
	nhiExposureFinding := object(map[string]*Schema{
		"inventory_id":       str(),
		"ref":                str(),
		"kind":               str(),
		"source":             str(),
		"display_name":       str(),
		"owner_id":           uuid(),
		"owner_status":       {Type: "string", Enum: []string{"owned", "subject_bound", "orphaned"}},
		"status":             str(),
		"severity":           {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score":         {Type: "integer"},
		"finding_types":      {Type: "array", Items: str()},
		"exposure_level":     str(),
		"network_surface":    str(),
		"public_endpoints":   {Type: "array", Items: str()},
		"callback_urls":      {Type: "array", Items: str()},
		"transport_security": str(),
		"auth_mode":          str(),
		"environment":        str(),
		"recommendation":     str(),
		"evidence_refs":      {Type: "array", Items: str()},
	}, "inventory_id", "kind", "source", "display_name", "owner_status", "status", "severity", "risk_score", "finding_types", "exposure_level", "network_surface", "public_endpoints", "callback_urls", "transport_security", "auth_mode", "recommendation", "evidence_refs")
	nhiExposurePosture := object(map[string]*Schema{
		"capability":   str(),
		"generated_at": timestamp(),
		"coverage":     {Type: "array", Items: str()},
		"summary":      ref("NHIExposureSummary"),
		"findings":     {Type: "array", Items: ref("NHIExposureFinding")},
	}, "capability", "generated_at", "coverage", "summary", "findings")
	nhiDecommissionSignal := object(map[string]*Schema{
		"type":            {Type: "string", Enum: []string{"departure", "vendor_term", "inactivity"}},
		"subject":         str(),
		"owner_id":        uuid(),
		"owner_name":      str(),
		"vendor_name":     str(),
		"identity_id":     uuid(),
		"inactive_before": timestamp(),
		"evidence_refs":   {Type: "array", Items: str()},
	}, "type")
	nhiDecommissionRequest := object(map[string]*Schema{
		"reason":            str(),
		"revocation_reason": str(),
		"signals":           {Type: "array", Items: ref("NHIDecommissionSignal")},
	}, "signals")
	nhiDecommissionSummary := object(map[string]*Schema{
		"total_matched": {Type: "integer"},
		"revoked":       {Type: "integer"},
		"retired":       {Type: "integer"},
		"skipped":       {Type: "integer"},
		"failed":        {Type: "integer"},
	}, "total_matched", "revoked", "retired", "skipped", "failed")
	nhiDecommissionItem := object(map[string]*Schema{
		"identity_id":   uuid(),
		"name":          str(),
		"kind":          str(),
		"owner_id":      uuid(),
		"signal_type":   {Type: "string", Enum: []string{"departure", "vendor_term", "inactivity"}},
		"action":        {Type: "string", Enum: []string{"revoked", "retired", "skipped", "failed"}},
		"from":          str(),
		"to":            str(),
		"evidence_refs": {Type: "array", Items: str()},
		"error":         str(),
	}, "identity_id", "name", "kind", "owner_id", "signal_type", "action", "from", "to")
	nhiDecommissionResponse := object(map[string]*Schema{
		"capability": str(),
		"coverage":   {Type: "array", Items: str()},
		"reason":     str(),
		"summary":    ref("NHIDecommissionSummary"),
		"items":      {Type: "array", Items: ref("NHIDecommissionItem")},
	}, "capability", "coverage", "reason", "summary", "items")
	ownershipAttributionOwner := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: []string{"user", "team", "workload", "service", "vendor"}},
		"name": str(), "email": str(),
	}, "id", "tenant_id", "kind", "name")
	ownershipAttributionItem := object(map[string]*Schema{
		"id": str(), "tenant_id": uuid(), "kind": str(), "source": str(),
		"display_name": str(), "ref": str(), "owner": ref("OwnershipAttributionOwner"),
		"attribution_status":   {Type: "string", Enum: []string{"attributed", "orphaned"}},
		"attribution_source":   str(),
		"attribution_evidence": {Type: "array", Items: str()},
		"created_at":           timestamp(),
		"discovered_at":        timestamp(),
	}, "id", "tenant_id", "kind", "source", "display_name", "attribution_status", "attribution_source", "attribution_evidence", "created_at")
	ownershipAttribution := object(map[string]*Schema{
		"generated_at": timestamp(),
		"items":        {Type: "array", Items: ref("OwnershipAttributionItem")},
		"summary":      {Type: "object"},
		"coverage":     {Type: "array", Items: str()},
	}, "generated_at", "items", "summary", "coverage")
	connectorCatalogItem := object(map[string]*Schema{
		"name": str(), "kind": str(), "delivery_mode": str(), "rollback": str(),
		// D4: whether trstctl can PERFORM that rollback or only describe it.
		"executes_rollback": {Type: "boolean"},
		// E1: whether this family's deploy is exercised against a faithful
		// double of its device API, not only the in-memory conformance suite.
		"device_proven": {Type: "boolean"},
		// E3: what this repository can truthfully attest about the family.
		"support": ref("ConnectorSupportRow"),
		// B-6: live sandbox facts from the connector registry.
		"native":        {Type: "boolean"},
		"capabilities":  {Type: "array", Items: str()},
		"replay_safety": {Type: "string", Enum: []string{"at-most-once", "reconciled"}},
		// A3: where this connector's deploy work executes, from the live census.
		"target_vantage": {Type: "string", Enum: []string{"control_plane", "host_agent", "network_relay"}},
		// E1: present for every family in the accepted 13-family denominator,
		// including host/cloud families whose network-relay path is unimplemented.
		"relay_parity": ref("ConnectorRelayParity"),
	}, "name", "kind", "delivery_mode", "rollback", "native", "capabilities", "replay_safety", "target_vantage", "device_proven")
	// E1: which per-family gates a family has cleared, and which hold it back.
	// Missing gates are named rather than counted: "two gates left" invites a
	// reader to assume the remaining two are small and alike.
	connectorRelayParity := object(map[string]*Schema{
		"met":            {Type: "array", Items: str()},
		"missing":        {Type: "array", Items: str()},
		"outstanding":    {Type: "array", Items: str()},
		"disposition":    {Type: "string", Enum: []string{"migrated", "architecture_exception", "unimplemented"}},
		"relay_migrated": {Type: "boolean"},
		// cp_retained is a compatibility field for an open architecture
		// exception; disposition is the authoritative closed classification.
		"cp_retained": {Type: "boolean"},
		"scope_note":  str(),
		"detail":      str(),
	}, "met", "missing", "outstanding", "relay_migrated", "detail")
	// E3: deliberately no firmware version field. A version range is a claim
	// about hardware nothing here runs, and a schema field for one would invite
	// somebody to fill it.
	connectorSupportRow := object(map[string]*Schema{
		"api_contract":      str(),
		"proven_operations": {Type: "array", Items: str()},
		"known_limits":      {Type: "array", Items: str()},
		"hardware_tested":   {Type: "boolean"},
		"detail":            str(),
	}, "api_contract", "proven_operations", "known_limits", "hardware_tested", "detail")
	// J2: whether this deployment's backup was last VERIFIED, not merely taken.
	drArtifactFailure := object(map[string]*Schema{
		"name": str(), "required": {Type: "boolean"}, "detail": str(),
	}, "name", "required", "detail")
	drDrill := object(map[string]*Schema{
		"id":           str(),
		"outcome":      {Type: "string", Enum: []string{"restored", "failed", "skipped"}},
		"ran_at":       timestamp(),
		"completed_at": timestamp(),
		"rpo_seconds":  {Type: "integer"}, "rto_seconds": {Type: "integer"},
		"events_restored":           {Type: "integer"},
		"postgres_records_restored": {Type: "integer"},
		"postgres_tables_restored":  {Type: "object", AdditionalProperties: &Schema{Type: "integer"}},
		"artifacts_restored":        {Type: "array", Items: str()},
		"full_set_restored":         {Type: "boolean"},
		"store_healthy":             {Type: "boolean"},
		"event_log_healthy":         {Type: "boolean"},
		"signer_healthy":            {Type: "boolean"},
		"server_healthy":            {Type: "boolean"},
		"detail":                    str(),
		"limitations":               {Type: "array", Items: str()},
		"signature_verified":        {Type: "boolean"},
		"signer_key_id":             str(),
		"signer_algorithm":          str(),
		"signature":                 str(),
		"verification_jwks":         {Type: "object", AdditionalProperties: &Schema{}},
		"signed_evidence":           {Type: "object", AdditionalProperties: &Schema{}},
	}, "outcome", "ran_at", "rpo_seconds", "rto_seconds", "events_restored",
		"postgres_records_restored", "postgres_tables_restored", "artifacts_restored",
		"full_set_restored", "store_healthy", "event_log_healthy", "signer_healthy", "server_healthy",
		"detail", "limitations")
	drPosture := object(map[string]*Schema{
		"backup_configured":      {Type: "boolean"},
		"last_backup_at":         timestamp(),
		"last_verified_at":       timestamp(),
		"verified":               {Type: "boolean"},
		"artifacts_checked":      {Type: "integer"},
		"artifacts_unverifiable": {Type: "integer"},
		"failures":               {Type: "array", Items: ref("DRArtifactFailure")},
		"detail":                 str(), "guidance": str(),
		// J2: absent until a drill has run, and absent is the point — an
		// always-present object would give a never-drilled deployment a
		// zero-valued drill that reads as a clean one.
		"last_drill":    ref("DRDrill"),
		"drill_history": {Type: "array", Items: ref("DRDrill")},
	}, "backup_configured", "verified", "artifacts_checked", "artifacts_unverifiable", "detail", "guidance")
	// I4: recent enrolment refusals, classified.
	enrollmentDiagnostic := object(map[string]*Schema{
		"id":       str(),
		"protocol": {Type: "string", Enum: []string{"acme", "est", "scep", "cmp", "adcs"}},
		"step":     str(), "cause": str(), "summary": str(),
		"remediation": str(), "actionable": {Type: "boolean"},
		"observed_at": timestamp(), "count": {Type: "integer"},
		"operation_ref": str(), "identity_ref": str(), "endpoint_ref": str(),
		"verification_kind":    {Type: "string", Enum: []string{"endpoint.verify"}},
		"verification_address": str(), "verification_server_name": str(),
		"expected_fingerprint": str(), "verification_endpoint_id": str(),
		"verification_queued_at":       timestamp(),
		"verification_status":          {Type: "string", Enum: []string{"queued", "verified", "diverged", "unreachable"}},
		"verification_evidence_digest": str(), "verification_agent": str(),
		"verification_checked_at": timestamp(), "verification_result_path": str(),
	}, "id", "protocol", "step", "cause", "summary", "actionable", "observed_at", "count")
	enrollmentDiagnosticList := object(map[string]*Schema{
		"items":         {Type: "array", Items: ref("EnrollmentDiagnostic")},
		"unknown_count": {Type: "integer"},
		"guidance":      str(),
	}, "items", "unknown_count", "guidance")
	enrollmentDiagnosticVerification := object(map[string]*Schema{
		"diagnostic_id": str(), "verification_endpoint_id": str(),
		"status":    {Type: "string", Enum: []string{"queued"}},
		"queued_at": timestamp(), "result_path": str(),
	}, "diagnostic_id", "verification_endpoint_id", "status", "queued_at", "result_path")
	enrollmentDiagnosticSupportAggregate := object(map[string]*Schema{
		"protocol": {Type: "string", Enum: []string{"acme", "est", "scep", "cmp", "adcs"}},
		"cause":    str(), "actionable": {Type: "boolean"}, "count": {Type: "integer"},
	}, "protocol", "cause", "actionable", "count")
	enrollmentDiagnosticsSupportAddendum := object(map[string]*Schema{
		"schema_version": {Type: "integer"},
		"rows":           {Type: "array", Items: ref("EnrollmentDiagnosticSupportAggregate")},
		"unknown_count":  {Type: "integer"},
	}, "schema_version", "rows", "unknown_count")
	relayPluginGrant := object(map[string]*Schema{
		"capability":  {Type: "string", Enum: []string{"fs.read", "fs.write", "net.dial"}},
		"constraints": {Type: "array", Items: str()},
	}, "capability", "constraints")
	relayPluginEntry := object(map[string]*Schema{
		"name": str(), "digest": str(), "publisher": str(),
		"execution_context": {Type: "string", Enum: []string{"network_relay_wasm"}},
		"grants":            {Type: "array", Items: ref("RelayPluginGrant")},
	}, "name", "digest", "publisher", "execution_context", "grants")
	relayPluginRuntime := object(map[string]*Schema{
		"agent_id": uuid(), "agent_name": str(), "agent_status": str(),
		"reported_at": timestamp(), "signer_fingerprint": str(),
		"signature_verified": {Type: "boolean"}, "metadata_only": {Type: "boolean"},
		"plugins": {Type: "array", Items: ref("RelayPluginEntry")},
	}, "agent_id", "agent_name", "agent_status", "reported_at", "signer_fingerprint",
		"signature_verified", "metadata_only", "plugins")
	connectorCatalog := object(map[string]*Schema{
		"items":                     {Type: "array", Items: ref("ConnectorCatalogItem")},
		"relay_plugins":             {Type: "array", Items: ref("RelayPluginRuntime")},
		"relay_plugins_next_cursor": str(),
	}, "items")
	acmeDNS01ProviderCatalogItem := object(map[string]*Schema{
		"name":                        str(),
		"display_name":                str(),
		"kind":                        str(),
		"served":                      {Type: "boolean"},
		"propagation_preflight":       {Type: "boolean"},
		"conformance":                 str(),
		"admission_state":             str(),
		"provenance":                  str(),
		"credential_reference_fields": {Type: "array", Items: str()},
		"secret_fields":               {Type: "array", Items: str()},
		"capabilities":                {Type: "array", Items: str()},
		"provider_package":            str(),
		"notes":                       str(),
	}, "name", "display_name", "kind", "served", "propagation_preflight", "conformance", "credential_reference_fields", "secret_fields", "capabilities", "provider_package")
	acmeDNS01ProviderCatalog := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ACMEDNS01ProviderCatalogItem")},
	}, "items")
	acmeDNS01ProviderConfigReq := object(map[string]*Schema{
		"name": str(), "provider": str(), "zone": str(), "challenge_domain": str(),
		"delegation_target": str(), "credential_refs": {Type: "object"},
		"config": {Type: "object"}, "caa_issuer_domain": str(),
		"allowed_methods": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"http-01", "dns-01", "tls-alpn-01"}}},
		"allow_wildcards": {Type: "boolean"}, "allow_upstream_dv": {Type: "boolean"},
	}, "name", "provider")
	acmeDNS01ProviderConfig := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "provider": str(), "zone": str(),
		"challenge_domain": str(), "delegation_target": str(), "credential_refs": {Type: "object"},
		"config": {Type: "object"}, "caa_issuer_domain": str(),
		"allowed_methods": {Type: "array", Items: str()}, "allow_wildcards": {Type: "boolean"},
		"allow_upstream_dv": {Type: "boolean"},
		"secret_handling":   str(), "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "name", "provider", "credential_refs", "config", "allowed_methods", "secret_handling", "created_at", "updated_at")
	acmeDNS01ProviderConfigList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ACMEDNS01ProviderConfig")},
	}, "items")
	acmeDNS01PreflightReq := object(map[string]*Schema{
		"config_id": uuid(), "domain": str(), "method_override": {Type: "string", Enum: []string{"http-01", "dns-01", "tls-alpn-01"}},
		"expected_txt": str(), "observed_txt": {Type: "array", Items: str()}, "observed_cname": str(),
		"port80_reachable": {Type: "boolean"},
	}, "config_id", "domain")
	acmeDNS01PreflightCheck := object(map[string]*Schema{
		"name": str(), "status": {Type: "string", Enum: []string{"pass", "fail", "skipped"}}, "detail": str(),
	}, "name", "status", "detail")
	acmeDNS01CAAPolicyRecord := object(map[string]*Schema{
		"flag": {Type: "integer"}, "tag": str(), "value": str(),
	}, "flag", "tag", "value")
	acmeDNS01CAAPolicyEvidence := object(map[string]*Schema{
		"status":            {Type: "string", Enum: []string{"not_configured", "unrestricted", "allowed", "denied", "lookup_failed"}},
		"source":            {Type: "string", Enum: []string{"authoritative_live_dns"}},
		"configured_issuer": str(), "governing_name": str(), "wildcard": {Type: "boolean"},
		"relevant_tag":        {Type: "string", Enum: []string{"issue", "issuewild"}},
		"records":             {Type: "array", Items: ref("ACMEDNS01CAAPolicyRecord")},
		"allowed_issuers":     {Type: "array", Items: str()},
		"recommended_records": {Type: "array", Items: str()},
		"recovery_steps":      {Type: "array", Items: str()},
		"fail_closed":         {Type: "boolean"},
	}, "status", "source", "wildcard", "relevant_tag", "records", "allowed_issuers", "recommended_records", "recovery_steps", "fail_closed")
	acmeDNS01Preflight := object(map[string]*Schema{
		"ready": {Type: "boolean"}, "config_id": uuid(), "domain": str(), "record_name": str(),
		"selected_method": str(), "method_rationale": str(), "wildcard": {Type: "boolean"},
		"checks":        {Type: "array", Items: ref("ACMEDNS01PreflightCheck")},
		"failed_checks": {Type: "array", Items: str()},
		"caa_policy":    ref("ACMEDNS01CAAPolicyEvidence"),
	}, "ready", "config_id", "domain", "record_name", "selected_method", "wildcard", "checks", "failed_checks", "caa_policy")
	acmeDNS01QualificationReq := object(map[string]*Schema{
		"domain": str(),
	}, "domain")
	acmeDNS01QualificationCheck := object(map[string]*Schema{
		"id": str(), "label": str(), "passed": {Type: "boolean"}, "detail": str(), "recovery": str(),
	}, "id", "label", "passed", "detail", "recovery")
	acmeDNS01QualificationPreview := object(map[string]*Schema{
		"ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"config_id": uuid(), "config_name": str(), "provider": str(), "domain": str(),
		"record_name": str(), "wildcard": {Type: "boolean"},
		"credential_reference_fields": {Type: "array", Items: str()},
		"checks":                      {Type: "array", Items: ref("ACMEDNS01QualificationCheck")},
		"blockers":                    {Type: "array", Items: str()},
		"preview_writes":              {Type: "array", Items: str()},
		"preview_external_effects":    {Type: "array", Items: str()},
		"preview_signer_calls":        {Type: "array", Items: str()},
		"execute_writes":              {Type: "array", Items: str()},
		"execute_external_effects":    {Type: "array", Items: str()},
		"execute_signer_calls":        {Type: "array", Items: str()},
		"recovery_steps":              {Type: "array", Items: str()},
		"least_privilege_checklist":   {Type: "array", Items: str()},
		"secret_data_handling":        str(),
	}, "ready", "effect_free", "config_id", "config_name", "provider", "domain", "record_name", "wildcard",
		"credential_reference_fields", "checks", "blockers", "preview_writes", "preview_external_effects", "preview_signer_calls",
		"execute_writes", "execute_external_effects", "execute_signer_calls", "recovery_steps", "least_privilege_checklist", "secret_data_handling")
	acmeDNS01QualificationRun := object(map[string]*Schema{
		"id": uuid(), "config_id": uuid(), "config_name": str(), "provider": str(), "domain": str(), "record_name": str(),
		"status":             {Type: "string", Enum: []string{"running", "passed", "failed", "recovery_required"}},
		"stage":              {Type: "string", Enum: []string{"review", "publish", "propagation", "cleanup", "complete"}},
		"propagation_status": {Type: "string", Enum: []string{"not_run", "pending", "passed", "failed"}},
		"cleanup_status":     {Type: "string", Enum: []string{"not_needed", "pending", "delivered", "failed"}},
		"error_category":     str(), "attempts": {Type: "integer"}, "started_at": timestamp(), "completed_at": timestamp(),
		"duration_ms": {Type: "integer"}, "recovery_steps": {Type: "array", Items: str()}, "secret_data_handling": str(),
	}, "id", "config_id", "config_name", "provider", "domain", "record_name", "status", "stage", "propagation_status", "cleanup_status", "attempts", "started_at", "duration_ms", "recovery_steps", "secret_data_handling")
	acmeDNS01QualificationRunList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ACMEDNS01QualificationRun")},
	}, "items")
	acmeARIWindow := object(map[string]*Schema{
		"start": timestamp(),
		"end":   timestamp(),
	}, "start", "end")
	acmeARIPostureSummary := object(map[string]*Schema{
		"affected_certificates": {Type: "integer"},
		"published":             {Type: "integer"},
		"scheduler_pending":     {Type: "integer"},
		"scheduler_consumed":    {Type: "integer"},
		"scheduler_failed":      {Type: "integer"},
	}, "affected_certificates", "published", "scheduler_pending", "scheduler_consumed", "scheduler_failed")
	acmeARICertificatePosture := object(map[string]*Schema{
		"certificate_id":     uuid(),
		"identity_id":        uuid(),
		"identity_name":      str(),
		"ari_certificate_id": str(),
		"certificate_status": {Type: "string", Enum: []string{"active", "superseded", "revoked"}},
		"publication_status": {Type: "string", Enum: []string{
			ACMEARICertificatePublished,
			ACMEARICertificateNotPublished,
			ACMEARICertificateIdentifierUnavailable,
		}},
		"suggested_window": ref("ACMEARIWindow"),
		"scheduler_status": {Type: "string", Enum: []string{
			ACMEARIRunPending,
			ACMEARIRunRunning,
			ACMEARIRunSucceeded,
			ACMEARIRunFailed,
			ACMEARIRunNotApplicable,
		}},
		"scheduler_consumed": {Type: "boolean"},
		"scheduler_source": {Type: "string", Enum: []string{
			ACMEARISourceARI,
			ACMEARISourceFixedThreshold,
			ACMEARISourceManual,
			ACMEARISourceNone,
			ACMEARISourceUnknownScheduler,
		}},
		"rotation_run_id": uuid(),
		"consumed_at":     timestamp(),
	}, "certificate_id", "certificate_status", "publication_status", "scheduler_status", "scheduler_consumed", "scheduler_source")
	acmeARIPosture := object(map[string]*Schema{
		"served":               {Type: "boolean"},
		"generated_at":         timestamp(),
		"publication_status":   {Type: "string", Enum: []string{ACMEARIPublicationServed, ACMEARIPublicationNotServed}},
		"publication_endpoint": str(),
		"scheduler_status":     {Type: "string", Enum: []string{ACMEARISchedulerEnabled, ACMEARISchedulerDisabled}},
		"summary":              ref("ACMEARIPostureSummary"),
		"items":                {Type: "array", Items: ref("ACMEARICertificatePosture")},
		"next_cursor":          str(),
	}, "served", "generated_at", "publication_status", "publication_endpoint", "scheduler_status", "summary", "items")
	mdmSCEPPolicyReq := object(map[string]*Schema{
		"name": str(), "provider": {Type: "string", Enum: []string{"intune", "jamf"}},
		"scep_profile": str(), "scep_endpoint": str(), "expected_audience": str(),
		"challenge_mode":    {Type: "string", Enum: []string{"intune-jws", "hmac-dynamic"}},
		"trust_anchor_refs": {Type: "object"}, "profile_guidance": {Type: "object"},
		"enabled": {Type: "boolean"},
	}, "name", "provider", "scep_profile", "scep_endpoint")
	mdmSCEPPolicy := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "provider": str(),
		"scep_profile": str(), "scep_endpoint": str(), "expected_audience": str(),
		"challenge_mode": str(), "trust_anchor_refs": {Type: "object"},
		"profile_guidance": {Type: "object"}, "enabled": {Type: "boolean"},
		"rotation_version": {Type: "integer"}, "last_rotated_at": timestamp(),
		"created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "name", "provider", "scep_profile", "scep_endpoint", "challenge_mode", "trust_anchor_refs", "profile_guidance", "enabled", "rotation_version", "created_at", "updated_at")
	mdmSCEPPolicyList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("MDMSCEPPolicy")},
	}, "items")
	mdmSCEPPolicyPreview := object(map[string]*Schema{
		"capability": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"operation": {Type: "string", Enum: []string{"create", "update"}}, "policy_id": uuid(),
		"name": str(), "provider": {Type: "string", Enum: []string{"intune", "jamf"}},
		"scep_profile": str(), "scep_endpoint": str(), "expected_audience": str(),
		"challenge_mode":              {Type: "string", Enum: []string{"intune-jws", "hmac-dynamic"}},
		"enabled":                     {Type: "boolean"},
		"trust_anchor_reference_keys": {Type: "array", Items: str()},
		"profile_guidance":            {Type: "object"},
		"durable_writes":              {Type: "array", Items: str()},
		"outside_calls":               {Type: "array", Items: str()},
		"signer_calls":                {Type: "integer"},
		"blockers":                    {Type: "array", Items: str()},
		"recovery_steps":              {Type: "array", Items: str()},
		"secret_data_handling":        str(),
	}, "capability", "ready", "effect_free", "operation", "name", "provider", "scep_profile", "scep_endpoint", "challenge_mode", "enabled", "trust_anchor_reference_keys", "profile_guidance", "durable_writes", "outside_calls", "signer_calls", "blockers", "recovery_steps", "secret_data_handling")
	mdmSCEPTelemetry := object(map[string]*Schema{
		"allowed": {Type: "integer"}, "denied": {Type: "integer"}, "replay_rejected": {Type: "integer"},
		"last_failure_reason": str(), "last_transaction_id": str(), "last_event_timestamp": timestamp(),
	}, "allowed", "denied", "replay_rejected")
	mdmSCEPStatus := object(map[string]*Schema{
		"runtime_gate": str(), "runtime_note": str(), "telemetry": ref("MDMSCEPTelemetry"),
		"policies": {Type: "array", Items: ref("MDMSCEPPolicy")},
	}, "runtime_gate", "runtime_note", "telemetry", "policies")
	mdmSCEPChallengeRotated := object(map[string]*Schema{
		"policy": ref("MDMSCEPPolicy"),
	}, "policy")
	mdmSCEPChallengeRotationPreview := object(map[string]*Schema{
		"capability": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"policy_id": uuid(), "policy_name": str(),
		"current_version": {Type: "integer"}, "next_version": {Type: "integer"},
		"durable_writes":       {Type: "array", Items: str()},
		"outside_calls":        {Type: "array", Items: str()},
		"signer_calls":         {Type: "integer"},
		"blockers":             {Type: "array", Items: str()},
		"recovery_steps":       {Type: "array", Items: str()},
		"secret_data_handling": str(),
	}, "capability", "ready", "effect_free", "policy_id", "policy_name", "current_version", "next_version", "durable_writes", "outside_calls", "signer_calls", "blockers", "recovery_steps", "secret_data_handling")
	deploymentTargetReq := object(map[string]*Schema{
		"name": str(), "connector": str(), "config": {Type: "object"}, "enabled": {Type: "boolean"},
	}, "name", "connector")
	deploymentTarget := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "connector": str(), "config": {Type: "object"}, "enabled": {Type: "boolean"}, "created_at": timestamp(),
	}, "id", "tenant_id", "name", "connector", "config", "enabled", "created_at")
	identityConnectorTargetReq := object(map[string]*Schema{
		"target_id": uuid(),
	}, "target_id")
	endpointIssuer := object(map[string]*Schema{
		"source":       {Type: "string", Enum: []string{endpointIssuerPlatform, endpointIssuerPrivate, endpointIssuerExternal}},
		"id":           str(),
		"name":         str(),
		"type":         str(),
		"availability": str(),
	}, "source", "id")
	endpointBindingPlanReq := object(map[string]*Schema{
		"owner_id":            uuid(),
		"replace_identity_id": uuid(),
		"identity_name":       str(),
		"target_id":           uuid(),
		"target":              ref("DeploymentTargetRequest"),
		"issuer":              ref("EndpointIssuer"),
		"reason":              str(),
	}, "owner_id", "identity_name", "issuer")
	endpointBindingReq := object(map[string]*Schema{
		"owner_id":            uuid(),
		"replace_identity_id": uuid(),
		"identity_name":       str(),
		"target_id":           uuid(),
		"target":              ref("DeploymentTargetRequest"),
		"issuer":              ref("EndpointIssuer"),
		"reason":              str(),
		"preview_fingerprint": str(),
	}, "owner_id", "identity_name", "issuer", "preview_fingerprint")
	endpointBindingTarget := object(map[string]*Schema{
		"id": uuid(), "name": str(), "connector": str(), "config": {Type: "object"},
		"enabled": {Type: "boolean"}, "revision": str(),
	}, "name", "connector", "config", "enabled")
	endpointBindingCustody := object(map[string]*Schema{
		"key_origin": str(), "private_key_enters_control_plane": {Type: "boolean"}, "detail": str(),
	}, "key_origin", "private_key_enters_control_plane", "detail")
	endpointBindingPreview := object(map[string]*Schema{
		"issuance": object(map[string]*Schema{
			"profile_name": str(), "profile_id": uuid(), "profile_version": {Type: "integer"}, "profile_spec_digest": str(),
			"requested_ttl_seconds": {Type: "integer"}, "effective_ttl_seconds": {Type: "integer"},
		}, "requested_ttl_seconds", "effective_ttl_seconds"),
		"approval_required":         {Type: "boolean"},
		"existing_identity_version": {Type: "integer"},
		"capability":                str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"request_fingerprint": str(), "owner_id": uuid(), "identity_name": str(),
		"existing_identity":         ref("Identity"),
		"replaced_identity":         ref("Identity"),
		"replaced_identity_version": {Type: "integer"},
		"issuer":                    ref("EndpointIssuer"), "target": ref("EndpointBindingTarget"), "custody": ref("EndpointBindingCustody"),
		"changes": {Type: "array", Items: str()}, "queued_lifecycle_intents": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()}, "verification_steps": {Type: "array", Items: str()},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()},
	}, "issuance", "approval_required", "capability", "ready", "effect_free", "request_fingerprint", "owner_id", "identity_name", "issuer", "target", "custody", "changes", "queued_lifecycle_intents", "recovery_steps", "verification_steps", "preview_writes", "preview_external_effects")
	endpointBinding := object(map[string]*Schema{
		"identity":                 ref("Identity"),
		"replaced_identity_id":     uuid(),
		"target":                   ref("DeploymentTarget"),
		"issuer":                   ref("EndpointIssuer"),
		"preview_fingerprint":      str(),
		"queued_lifecycle_intents": {Type: "array", Items: str()},
		"renewal_intent":           str(),
	}, "identity", "target", "issuer", "preview_fingerprint", "queued_lifecycle_intents", "renewal_intent")
	connectorTargetActionReq := object(map[string]*Schema{
		"identity_id": uuid(), "reason": str(),
	}, "identity_id")
	connectorDelivery := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "outbox_id": {Type: "integer"}, "identity_id": uuid(),
		"destination": str(), "connector": str(), "target": str(), "fingerprint": str(),
		// Generated from the served status vocabulary so the published contract
		// cannot drift from what the code actually claims (internal/servedstatus).
		"status":   {Type: "string", Enum: servedstatus.ConnectorDelivery.Values()},
		"attempts": {Type: "integer"}, "reason": str(), "detail": str(), "rollback_ref": str(),
		"idempotency_key": str(), "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "destination", "connector", "target", "status", "attempts", "created_at", "updated_at")
	alertRecipient := object(map[string]*Schema{
		"kind": str(), "subject": str(), "display_name": str(), "email": str(),
		"roles": {Type: "array", Items: str()},
	}, "kind", "subject")
	notificationDelivery := object(map[string]*Schema{
		"id": str(), "channel": str(), "attempts": {Type: "integer"}, "delivered_at": timestamp(),
		"routing_source":    {Type: "string", Enum: []string{"explicit_policy", "inherited_policy", "default_policy", "all_channels", "channel_test"}, Description: "Selection used by this successful channel. Absent on historical receipts that did not retain routing evidence."},
		"routing_policy_id": str(), "routing_policy_scope": str(), "routing_policy_digest": str(),
	}, "id", "channel", "attempts", "delivered_at")
	notification := object(map[string]*Schema{
		"id": str(), "tenant_id": uuid(), "destination": str(), "kind": str(),
		"identity_id": uuid(), "operation_id": str(),
		"rotation_run_id": uuid(), "renewal_job_id": {Type: "integer", Format: "int64"}, "renewal_attempt": {Type: "integer", Description: "Historical failed host-job attempt; separate from notification delivery attempts."},
		"certificate_fingerprint": str(), "deployment_receipt_id": uuid(),
		"deployment_recorded_at": {Type: "string", Format: "date-time", Description: "Historical completion receipt captured with the alert. Certificate expiry describes this deployment or rollback, not a fresh listener probe."},
		"certificate_id":         str(), "subject": str(), "serial": str(), "not_after": timestamp(),
		"detail": str(), "severity": {Type: "string", Enum: []string{"low", "informational", "warning", "critical"}},
		"routing_policy_id": str(), "threshold_days": {Type: "integer"},
		"owner_id": uuid(), "owner_name": str(), "owner_email": str(),
		"escalation_recipients": {Type: "array", Items: ref("AlertRecipient")},
		"status":                {Type: "string", Enum: []string{"pending", "sent", "dead", "read"}},
		"attempts":              {Type: "integer"}, "last_error": str(), "idempotency_key": str(),
		"created_at": timestamp(), "delivered_at": timestamp(), "read_at": timestamp(),
		"deliveries": {Type: "array", Items: ref("NotificationDelivery"), Description: "Successful channel receipts for this exact command, included on notification detail reads. Current policy changes do not rewrite historical receipts."},
	}, "id", "tenant_id", "destination", "status", "attempts", "created_at")
	notificationChannel := object(map[string]*Schema{
		"id":                  str(),
		"channel_type":        str(),
		"label":               str(),
		"category":            str(),
		"configured":          {Type: "boolean"},
		"enabled":             {Type: "boolean"},
		"delivery":            str(),
		"description":         str(),
		"source":              str(),
		"endpoint_configured": {Type: "boolean"},
		"credential_ref":      str(),
		"secret_handling":     str(),
	}, "id", "label", "category", "configured", "enabled", "delivery")
	notificationChannelReq := object(map[string]*Schema{
		"id":             str(),
		"channel_type":   str(),
		"label":          str(),
		"endpoint_url":   str(),
		"credential_ref": str(),
		"enabled":        {Type: "boolean"},
	})
	notificationRoutingPolicyReq := object(map[string]*Schema{
		"id":                      uuid(),
		"name":                    str(),
		"scope_kind":              {Type: "string", Enum: []string{"manual", "global", "workspace", "owner", "asset"}},
		"scope_ref":               str(),
		"channels_by_severity":    {Type: "object"},
		"default_channels":        {Type: "array", Items: str()},
		"owner_ref":               str(),
		"owner_email":             str(),
		"digest_interval_seconds": {Type: "integer"},
		"digest_timezone":         str(),
	}, "name")
	notificationDigestPreview := object(map[string]*Schema{
		"interval_seconds": {Type: "integer"},
		"timezone":         str(),
		"next_run_at":      timestamp(),
	}, "interval_seconds", "timezone", "next_run_at")
	notificationRoutingPolicy := object(map[string]*Schema{
		"id":                      uuid(),
		"tenant_id":               uuid(),
		"name":                    str(),
		"scope_kind":              {Type: "string", Enum: []string{"manual", "global", "workspace", "owner", "asset"}},
		"scope_ref":               str(),
		"channels_by_severity":    {Type: "object"},
		"default_channels":        {Type: "array", Items: str()},
		"owner_ref":               str(),
		"owner_email":             str(),
		"digest_interval_seconds": {Type: "integer"},
		"digest_timezone":         str(),
		"digest_preview":          ref("NotificationDigestPreview"),
		"created_at":              timestamp(),
		"updated_at":              timestamp(),
	}, "id", "tenant_id", "name", "scope_kind", "channels_by_severity", "default_channels", "digest_interval_seconds", "digest_timezone", "digest_preview", "created_at", "updated_at")
	notificationRoutingPreview := object(map[string]*Schema{
		"resolution_order":   {Type: "array", Items: str()},
		"matched_policy":     ref("NotificationRoutingPolicy"),
		"effective_channels": {Type: "array", Items: str()},
		"missing_channels":   {Type: "array", Items: str()},
		"delivery_ready":     {Type: "boolean"},
		"explanation":        str(),
	}, "resolution_order", "effective_channels", "missing_channels", "delivery_ready", "explanation")
	notificationRoutingPolicyPreview := object(map[string]*Schema{
		"capability":               str(),
		"operation":                str(),
		"ready":                    {Type: "boolean"},
		"effect_free":              {Type: "boolean"},
		"request_fingerprint":      str(),
		"name":                     str(),
		"scope_kind":               {Type: "string", Enum: []string{"manual", "global", "workspace", "owner", "asset"}},
		"scope_ref":                str(),
		"channels_by_severity":     {Type: "object"},
		"default_channels":         {Type: "array", Items: str()},
		"owner_ref":                str(),
		"owner_email":              str(),
		"digest_interval_seconds":  {Type: "integer"},
		"digest_timezone":          str(),
		"configured_channels":      {Type: "array", Items: str()},
		"missing_channels":         {Type: "array", Items: str()},
		"blockers":                 {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_writes":           {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"secret_data_handling":     str(),
	}, "capability", "operation", "ready", "effect_free", "request_fingerprint", "name", "scope_kind", "channels_by_severity", "default_channels", "digest_interval_seconds", "digest_timezone", "configured_channels", "missing_channels", "blockers", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "secret_data_handling")
	notificationChannelTestReq := object(map[string]*Schema{
		"subject":           str(),
		"severity":          {Type: "string", Enum: []string{"low", "informational", "warning", "critical"}},
		"detail":            str(),
		"routing_policy_id": uuid(),
		"credential_ref":    str(),
		"owner_email":       str(),
	})
	notificationChannelTest := object(map[string]*Schema{
		"channel_id":      str(),
		"destination":     str(),
		"outbox_id":       {Type: "integer"},
		"status":          {Type: "string", Enum: []string{"queued"}},
		"credential_ref":  str(),
		"secret_handling": str(),
		"idempotency_key": str(),
		"queued_at":       timestamp(),
	}, "channel_id", "destination", "outbox_id", "status", "secret_handling", "idempotency_key", "queued_at")
	policyDryRunReq := object(map[string]*Schema{
		"kind":        {Type: "string", Enum: []string{"lifecycle", "abac"}},
		"module":      str(),
		"input":       {Type: "object"},
		"trace_limit": {Type: "integer"},
	})
	policyDryRunTrace := object(map[string]*Schema{
		"op":        str(),
		"query_id":  {Type: "integer"},
		"parent_id": {Type: "integer"},
		"location":  str(),
		"node":      str(),
		"message":   str(),
	}, "op", "query_id")
	policyDryRunInputSummary := object(map[string]*Schema{
		"action": str(), "permission": str(), "profile": str(), "subject": str(), "actor": str(), "tenant_id": uuid(),
	}, "tenant_id")
	policyDryRun := object(map[string]*Schema{
		"kind":            {Type: "string", Enum: []string{"lifecycle", "abac"}},
		"valid":           {Type: "boolean"},
		"module_sha256":   str(),
		"package":         str(),
		"query":           str(),
		"allow":           {Type: "boolean"},
		"deny":            {Type: "boolean"},
		"reason":          str(),
		"error":           str(),
		"trace":           {Type: "array", Items: ref("PolicyDryRunTrace")},
		"input_summary":   ref("PolicyDryRunInputSummary"),
		"audit_event":     str(),
		"idempotency_key": str(),
	}, "kind", "valid", "module_sha256", "package", "query", "allow", "deny", "trace", "input_summary", "audit_event", "idempotency_key")
	policyVersionReq := object(map[string]*Schema{
		"id":            uuid(),
		"kind":          {Type: "string", Enum: []string{"lifecycle"}},
		"module":        str(),
		"description":   str(),
		"change_ref":    str(),
		"evidence_refs": {Type: "array", Items: str()},
	}, "module")
	policyVersionActionReq := object(map[string]*Schema{
		"reason":        str(),
		"evidence_refs": {Type: "array", Items: str()},
	}, "reason")
	policyVersion := object(map[string]*Schema{
		"id":               uuid(),
		"tenant_id":        uuid(),
		"kind":             {Type: "string", Enum: []string{"lifecycle"}},
		"module":           str(),
		"module_sha256":    str(),
		"package":          str(),
		"query":            str(),
		"description":      str(),
		"change_ref":       str(),
		"evidence_refs":    {Type: "array", Items: str()},
		"status":           {Type: "string", Enum: []string{"draft", "active", "inactive", "rolled_back"}},
		"active":           {Type: "boolean"},
		"created_by":       str(),
		"activated_by":     str(),
		"created_at":       timestamp(),
		"activated_at":     timestamp(),
		"updated_at":       timestamp(),
		"rolled_back_at":   timestamp(),
		"rollback_from_id": uuid(),
		"rollback_to_id":   uuid(),
		"audit_event":      str(),
		"idempotency_key":  str(),
	}, "id", "tenant_id", "kind", "module_sha256", "package", "query", "evidence_refs", "status", "active")
	policyVersionListSummary := object(map[string]*Schema{
		"total":       {Type: "integer"},
		"active":      {Type: "integer"},
		"draft":       {Type: "integer"},
		"inactive":    {Type: "integer"},
		"rolled_back": {Type: "integer"},
	}, "total", "active", "draft", "inactive", "rolled_back")
	policyVersionList := object(map[string]*Schema{
		"items":  {Type: "array", Items: ref("PolicyVersion")},
		"active": ref("PolicyVersion"),
		"counts": ref("PolicyVersionListSummary"),
	}, "items", "counts")
	outboxCircuit := object(map[string]*Schema{
		"tenant_id": uuid(), "destination": str(),
		"state":      {Type: "string", Enum: []string{"closed", "open", "half-open"}},
		"failures":   {Type: "integer"},
		"open_until": timestamp(), "updated_at": timestamp(), "last_error": str(),
	}, "tenant_id", "destination", "state", "failures", "updated_at")
	// B-4: signing operations with transparency-log verification state.
	codeSigningIdentity := object(map[string]*Schema{
		"operation_id": str(), "mode": {Type: "string", Enum: []string{"managed", "keyless"}},
		"status": str(), "request_hash": str(),
		"transparency":       {Type: "string", Enum: []string{"verified", "pending", "failed", "not-published"}},
		"transparency_error": str(), "last_error": str(),
		"created_at": timestamp(), "updated_at": timestamp(),
	}, "operation_id", "mode", "status", "request_hash", "transparency", "created_at", "updated_at")
	codeSigningIdentityList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("CodeSigningIdentity")},
		"total": {Type: "integer"}, "verified_count": {Type: "integer"},
		"not_published_count": {Type: "integer"},
	}, "items", "total", "verified_count", "not_published_count")
	// B-2: hosts with standing SSH key access that is not under the CA.
	sshFleetHost := object(map[string]*Schema{
		"location": str(), "keys": {Type: "integer"},
		"standing_keys": {Type: "integer"}, "orphaned_keys": {Type: "integer"},
		"key_types": {Type: "array", Items: str()}, "sources": {Type: "array", Items: str()},
		"first_observed": timestamp(), "last_observed": timestamp(),
		"under_ca": {Type: "boolean"},
	}, "location", "keys", "standing_keys", "orphaned_keys", "key_types", "sources", "first_observed", "last_observed", "under_ca")
	sshFleetInventory := object(map[string]*Schema{
		"hosts":      {Type: "array", Items: ref("SSHFleetHost")},
		"host_count": {Type: "integer"}, "key_count": {Type: "integer"},
		"standing_key_count": {Type: "integer"}, "orphaned_key_count": {Type: "integer"},
		"hosts_not_under_ca": {Type: "integer"},
	}, "hosts", "host_count", "key_count", "standing_key_count", "orphaned_key_count", "hosts_not_under_ca")
	// B-5: running build, uptime, signer topology, and spine reachability.
	systemDependency := object(map[string]*Schema{
		"name": str(), "ready": {Type: "boolean"}, "error": str(),
	}, "name", "ready")
	idempotencyResultProtection := object(map[string]*Schema{
		"state":       {Type: "string", Enum: []string{"unavailable", "empty", "ready_for_ratchet", "partial", "failed", "recovery_required", "complete"}},
		"fleet_ready": {Type: "boolean"}, "sealed_only_floor": {Type: "boolean"},
		"raw_v0_remaining": {Type: "integer"}, "legacy_dynamic_remaining": {Type: "integer"},
		"sealed_results": {Type: "integer"}, "pending_results": {Type: "integer"},
		"indeterminate_results": {Type: "integer"}, "failure": str(), "recovery": str(),
	}, "state", "fleet_ready", "sealed_only_floor", "raw_v0_remaining", "legacy_dynamic_remaining", "sealed_results", "pending_results", "indeterminate_results", "recovery")
	tenantKeyDomainMigrateRequest := object(map[string]*Schema{
		"wrapper_kind": {Type: "string", Enum: []string{"local_file"}},
		"wrapper_id":   str(),
	}, "wrapper_id")
	tenantKeyDomainSealReceipt := object(map[string]*Schema{
		"accepted": {Type: "boolean"}, "operation_id": uuid(),
		"state": str(), "status_url": str(),
	}, "accepted", "operation_id", "state", "status_url")
	tenantKeyDomainStatus := object(map[string]*Schema{
		"served": {Type: "boolean"}, "protection_mode": str(), "state": str(),
		"domain_id": uuid(), "generation": {Type: "integer"},
		"wrapper_kind": str(), "wrapper_id": str(), "operation_id": uuid(),
		"operation_kind": str(), "operation_status": str(), "migration_stage": str(),
		"progress_completed": {Type: "integer"}, "progress_total": {Type: "integer"},
		"retryable": {Type: "boolean"}, "failure_code": str(), "failure": str(),
		"legacy_history_exposure": str(), "last_transition_type": str(),
		"last_transition_actor": str(), "last_transition_at": timestamp(),
		"last_transition_evidence_refs": {Type: "array", Items: str()},
		"local_wrapper_zero_egress":     {Type: "boolean"}, "remote_wrapper_state": str(),
		"recovery": str(),
	}, "served", "protection_mode", "state", "progress_completed", "progress_total", "retryable", "legacy_history_exposure", "last_transition_evidence_refs", "local_wrapper_zero_egress", "remote_wrapper_state", "recovery")
	systemReadout := object(map[string]*Schema{
		"version": str(), "commit": str(), "build_date": str(), "go_version": str(),
		"started_at": timestamp(), "uptime_seconds": {Type: "integer"},
		"signer_mode":         {Type: "string", Enum: []string{"child", "external", "none"}},
		"fips_module_active":  {Type: "boolean"},
		"dependencies":        {Type: "array", Items: ref("SystemDependency")},
		"idempotency_results": ref("IdempotencyResultProtectionReadout"),
		"deployment":          ref("DeploymentTriState"),
	}, "version", "commit", "build_date", "go_version", "started_at", "uptime_seconds", "signer_mode", "fips_module_active", "dependencies", "idempotency_results")
	// B-1: bounded worker-pool pressure (AN-7) as served telemetry.
	bulkheadPool := object(map[string]*Schema{
		"name": str(), "workers": {Type: "integer"}, "capacity": {Type: "integer"},
		"queued": {Type: "integer"}, "submitted": {Type: "integer"}, "completed": {Type: "integer"},
		"rejected": {Type: "integer"}, "panicked": {Type: "integer"}, "saturation_percent": {Type: "integer"},
	}, "name", "workers", "capacity", "queued", "submitted", "completed", "rejected", "panicked", "saturation_percent")
	bulkheadStats := object(map[string]*Schema{
		"served": {Type: "boolean"},
		"pools":  {Type: "array", Items: ref("BulkheadPool")},
	}, "served", "pools")
	rotationRun := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "identity_id": uuid(), "outbox_id": {Type: "integer"},
		"status":  {Type: "string", Enum: []string{"running", "succeeded", "failed", "cancelled"}, Description: "Cancelled means retained identity revocation or retirement stopped queued issuance work; it does not undo an external effect."},
		"trigger": str(), "reason": str(), "predecessor_fingerprint": str(),
		"successor_fingerprint": str(), "rollback_ref": str(), "error": str(),
		"idempotency_key": str(), "created_at": timestamp(), "updated_at": timestamp(),
		"completed_at": timestamp(),
		"host_job": object(map[string]*Schema{
			"id": {Type: "integer", Format: "int64"}, "status": str(), "attempts": {Type: "integer"}, "completed_at": timestamp(),
		}, "id", "status", "attempts"),
	}, "id", "tenant_id", "identity_id", "status", "trigger", "created_at", "updated_at")
	lifecycleAutomationScheduler := object(map[string]*Schema{
		"status":       {Type: "string", Enum: []string{"running", "deferred", "disabled"}},
		"renew_before": str(), "renew_before_seconds": {Type: "integer"},
		"alert_before": str(), "alert_before_seconds": {Type: "integer"},
		"interval": str(), "interval_seconds": {Type: "integer"},
		"ari_first":                 {Type: "boolean"},
		"maintenance_window_status": {Type: "string", Enum: []string{"open", "closed"}},
		"maintenance_deferral":      str(), "next_open": timestamp(),
	}, "status", "renew_before", "renew_before_seconds", "alert_before", "alert_before_seconds", "interval", "interval_seconds", "ari_first", "maintenance_window_status")
	lifecycleAutomationSummary := object(map[string]*Schema{
		"monitored": {Type: "integer"}, "due_now": {Type: "integer"}, "renewal_failed": {Type: "integer"},
		"outbox_pending": {Type: "integer"}, "outbox_processing": {Type: "integer"}, "outbox_failed": {Type: "integer"},
	}, "monitored", "due_now", "renewal_failed", "outbox_pending", "outbox_processing", "outbox_failed")
	lifecycleAutomationItem := object(map[string]*Schema{
		"identity_id": uuid(), "identity_name": str(), "identity_status": str(),
		"owner_id": uuid(), "owner_name": str(), "certificate_id": uuid(), "not_after": timestamp(),
		"due": {Type: "boolean"}, "renewal_source": {Type: "string", Enum: []string{"ari", "fixed_deadline", "not_due", "in_flight"}},
		"reason": str(), "latest_run_id": uuid(), "latest_run_status": str(), "rollback_ref": str(),
		"blockers": {Type: "array", Items: str()},
	}, "identity_id", "identity_name", "identity_status", "owner_id", "owner_name", "certificate_id", "due", "renewal_source", "reason", "blockers")
	lifecycleAutomationControl := object(map[string]*Schema{
		"action": {Type: "string", Enum: []string{"start", "pause", "resume", "retry", "cancel", "rollback"}},
		"state":  {Type: "string", Enum: []string{"available", "configuration_only", "automatic", "conditional", "unavailable_after_enqueue"}},
		"detail": str(),
	}, "action", "state", "detail")
	lifecycleAutomationPlan := object(map[string]*Schema{
		"capability": str(), "ready": {Type: "boolean"}, "generated_at": timestamp(),
		"scheduler": ref("LifecycleAutomationScheduler"), "summary": ref("LifecycleAutomationSummary"),
		"items":                      {Type: "array", Items: ref("LifecycleAutomationItem")},
		"controls":                   {Type: "array", Items: ref("LifecycleAutomationControl")},
		"preview_writes":             {Type: "array", Items: str()},
		"preview_external_effects":   {Type: "array", Items: str()},
		"execution_writes":           {Type: "array", Items: str()},
		"execution_external_effects": {Type: "array", Items: str()},
		"verification_steps":         {Type: "array", Items: str()},
	}, "capability", "ready", "generated_at", "scheduler", "summary", "items", "controls", "preview_writes", "preview_external_effects", "execution_writes", "execution_external_effects", "verification_steps")
	incidentExecutionReq := object(map[string]*Schema{
		"identity_id": uuid(), "reason": str(), "replacement_name": str(),
		"connector": str(), "target": str(), "delivery_rollback_ref": str(),
	}, "identity_id")
	remediationPlaybook := object(map[string]*Schema{
		"id": str(), "name": str(), "action": str(), "status": str(), "capability": str(),
		"summary": str(), "external_effect": str(),
		"required_inputs":  {Type: "array", Items: str()},
		"evidence_sources": {Type: "array", Items: str()},
	}, "id", "name", "action", "status", "capability", "summary", "external_effect", "required_inputs", "evidence_sources")
	remediationPlaybookCatalog := object(map[string]*Schema{
		"capability": str(), "status": str(), "generated_at": timestamp(),
		"items": {Type: "array", Items: ref("RemediationPlaybook")},
	}, "capability", "status", "generated_at", "items")
	remediationPlaybookRunReq := object(map[string]*Schema{
		"target_identity_id": uuid(), "inventory_id": str(), "reason": str(),
		"connector": str(), "target": str(), "replacement_name": str(),
		"remove_scopes":      {Type: "array", Items: str()},
		"recommended_scopes": {Type: "array", Items: str()},
		"rollback_ref":       str(),
	})
	remediationPlaybookRun := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "playbook_id": str(),
		"target_identity_id": str(), "inventory_id": str(),
		"status": str(), "phase": str(), "action": str(), "reason": str(),
		"connector": str(), "target": str(), "outbox_id": {Type: "integer"},
		"connector_delivery_id": uuid(), "scope_delta": {Type: "object"},
		"evidence_refs": {Type: "array", Items: str()}, "rollback_refs": {Type: "array", Items: str()},
		"idempotency_key": str(), "created_by": str(), "created_at": timestamp(), "updated_at": timestamp(),
		"connector_delivery": ref("ConnectorDelivery"),
	}, "id", "tenant_id", "playbook_id", "status", "phase", "action", "scope_delta", "evidence_refs", "rollback_refs", "created_at", "updated_at")
	ownerRemediationSummary := object(map[string]*Schema{
		"total": {Type: "integer"}, "open": {Type: "integer"}, "accepted": {Type: "integer"},
		"critical": {Type: "integer"}, "high": {Type: "integer"}, "medium": {Type: "integer"}, "low": {Type: "integer"},
	}, "total", "open", "accepted", "critical", "high", "medium", "low")
	ownerRemediationAction := object(map[string]*Schema{
		"id": str(), "owner_id": uuid(), "owner_name": str(), "owner_email": str(),
		"inventory_id": str(), "target_identity_id": str(), "display_name": str(),
		"kind": str(), "source": str(), "playbook_id": str(), "action": str(), "status": str(),
		"severity":   {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"risk_score": {Type: "integer"}, "connector": str(), "target": str(), "reason": str(),
		"recommendation": str(), "remove_scopes": {Type: "array", Items: str()},
		"recommended_scopes": {Type: "array", Items: str()}, "evidence_refs": {Type: "array", Items: str()},
		"rollback_ref": str(), "remediation_run_id": uuid(), "connector_delivery_id": uuid(),
	}, "id", "owner_id", "owner_name", "inventory_id", "display_name", "kind", "source", "playbook_id", "action", "status", "severity", "risk_score", "connector", "target", "reason", "recommendation", "remove_scopes", "recommended_scopes", "evidence_refs", "rollback_ref")
	ownerRemediationQueue := object(map[string]*Schema{
		"capability": str(), "status": str(), "generated_at": timestamp(),
		"summary":       ref("OwnerRemediationSummary"),
		"items":         {Type: "array", Items: ref("OwnerRemediationAction")},
		"evidence_refs": {Type: "array", Items: str()},
	}, "capability", "status", "generated_at", "summary", "items", "evidence_refs")
	ownerRemediationAcceptReq := object(map[string]*Schema{
		"reason": str(), "connector": str(), "target": str(),
		"remove_scopes":      {Type: "array", Items: str()},
		"recommended_scopes": {Type: "array", Items: str()},
		"rollback_ref":       str(),
	})
	ownerRemediationRun := object(map[string]*Schema{
		"capability":      str(),
		"status":          str(),
		"action":          ref("OwnerRemediationAction"),
		"remediation_run": ref("RemediationPlaybookRun"),
	}, "capability", "status", "action", "remediation_run")
	// Legacy D6 rows retain open operator gates. H3 rows use the same response
	// shape, but their verdicts come only from H2's signed trust/live receipts and
	// the exact predecessor-revocation receipt.
	fleetHealthGate := object(map[string]*Schema{
		"name": str(), "status": str(),
	}, "name", "status")
	fleetBatch := object(map[string]*Schema{
		"index": {Type: "integer"}, "status": {Type: "string", Enum: servedstatus.FleetBatch.Values()},
		"identity_ids":             {Type: "array", Items: uuid()},
		"replacement_identity_ids": {Type: "array", Items: uuid()},
		"health_gate":              str(),
	}, "index", "status", "identity_ids", "replacement_identity_ids")
	fleetReissuanceReq := object(map[string]*Schema{
		"issuer_id": uuid(), "replacement_authority_id": uuid(),
		"mode":   {Type: "string", Enum: []string{"live", "game_day"}},
		"reason": str(), "cohorts": {Type: "array", Items: ref("MigrationRunStartWave")},
		"rollback_ref": str(),
	}, "issuer_id", "replacement_authority_id", "mode", "cohorts")
	fleetReissuanceActionReq := object(map[string]*Schema{
		"reason": str(), "rollback_ref": str(),
	})
	serviceNowTicketReq := object(map[string]*Schema{
		"instance_url":           str(),
		"table":                  {Type: "string", Enum: []string{"incident", "change_request", "sc_task"}},
		"token_ref":              str(),
		"short_description":      str(),
		"description":            str(),
		"category":               str(),
		"urgency":                str(),
		"impact":                 str(),
		"correlation_id":         str(),
		"allow_private_endpoint": {Type: "boolean"},
	}, "instance_url", "token_ref", "short_description")
	responseIntegrationDestinationReq := object(map[string]*Schema{
		"id":                     str(),
		"provider":               {Type: "string", Enum: []string{"splunk", "jira", "slack", "servicenow"}},
		"endpoint_url":           str(),
		"instance_url":           str(),
		"token_ref":              str(),
		"project_key":            str(),
		"issue_type":             str(),
		"table":                  {Type: "string", Enum: []string{"incident", "change_request", "sc_task"}},
		"channel":                str(),
		"allow_private_endpoint": {Type: "boolean"},
		"private_egress_cidrs":   {Type: "array", Items: str()},
	}, "provider")
	responseIntegrationDispatchReq := object(map[string]*Schema{
		"incident_id":        str(),
		"remediation_run_id": str(),
		"title":              str(),
		"summary":            str(),
		"severity":           {Type: "string", Enum: []string{"low", "informational", "warning", "critical"}},
		"correlation_id":     str(),
		"evidence_refs":      {Type: "array", Items: str()},
		"destinations":       {Type: "array", Items: ref("ResponseIntegrationDestinationRequest")},
	}, "title", "destinations")
	responseIntegrationQueuedDestination := object(map[string]*Schema{
		"id":              str(),
		"provider":        str(),
		"destination":     str(),
		"status":          str(),
		"outbox_id":       {Type: "integer"},
		"idempotency_key": str(),
	}, "id", "provider", "destination", "status", "outbox_id", "idempotency_key")
	responseIntegrationDispatch := object(map[string]*Schema{
		"id":              str(),
		"tenant_id":       uuid(),
		"status":          str(),
		"idempotency_key": str(),
		"created_at":      timestamp(),
		"destinations":    {Type: "array", Items: ref("ResponseIntegrationQueuedDestination")},
	}, "id", "tenant_id", "status", "idempotency_key", "created_at", "destinations")
	role := object(map[string]*Schema{
		"name": str(), "permissions": {Type: "array", Items: str()},
	}, "name", "permissions")
	oidcTenantMapping := object(map[string]*Schema{
		"subject": str(), "claim": str(), "group": str(), "tenant_id": uuid(),
		"roles": {Type: "array", Items: str()},
	}, "tenant_id")
	oidcMappingStatus := object(map[string]*Schema{
		"enabled": {Type: "boolean"}, "tenant_claim": str(), "groups_claim": str(),
		"claim_is_tenant": {Type: "boolean"}, "default_roles": {Type: "array", Items: str()},
		"default_tenant": uuid(), "allow_default_tenant": {Type: "boolean"},
		"tenant_mappings": {Type: "array", Items: ref("OIDCTenantMapping")},
	}, "enabled", "claim_is_tenant", "allow_default_tenant", "tenant_mappings")
	member := object(map[string]*Schema{
		"tenant_id": uuid(), "subject": str(), "display_name": str(), "email": str(),
		"roles": {Type: "array", Items: str()}, "source": str(),
		"status":     {Type: "string", Enum: []string{"active", "offboarded"}},
		"created_at": timestamp(), "updated_at": timestamp(), "offboarded_at": timestamp(),
		"offboarded_by": str(), "offboard_reason": str(),
	}, "tenant_id", "subject", "roles", "source", "status", "created_at", "updated_at")
	memberReq := object(map[string]*Schema{
		"display_name": str(), "email": str(), "roles": {Type: "array", Items: str()}, "source": str(),
	}, "roles")
	offboardMemberReq := object(map[string]*Schema{"reason": str()})
	offboardMemberResp := object(map[string]*Schema{
		"member": ref("Member"), "revoked_token_count": {Type: "integer"}, "rotation_evidence": str(),
	}, "member", "revoked_token_count", "rotation_evidence")
	apiToken := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "subject": str(), "scopes": {Type: "array", Items: str()},
		"expires_at": timestamp(), "created_at": timestamp(), "revoked_at": timestamp(),
		"revoked_by": str(), "revocation_reason": str(),
	}, "id", "tenant_id", "subject", "scopes", "created_at")
	apiTokenCreateReq := object(map[string]*Schema{
		"subject": str(), "scopes": {Type: "array", Items: str()}, "expires_at": timestamp(),
	}, "subject", "scopes")
	apiTokenCreateResp := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "subject": str(), "scopes": {Type: "array", Items: str()},
		"expires_at": timestamp(), "created_at": timestamp(), "token": str(),
	}, "id", "tenant_id", "subject", "scopes", "created_at", "token")
	apiTokenRevokeReq := object(map[string]*Schema{"reason": str()})
	ephemeralAPIKeyReq := object(map[string]*Schema{
		"subject": str(), "scopes": {Type: "array", Items: str()}, "ttl_seconds": {Type: "integer"},
		"preview_fingerprint": {Type: "string", Description: "Optional server-keyed fingerprint returned by EphemeralAPIKeyPreview. When supplied, issuance fails closed if subject, scopes, caller, tenant, or lifetime changed."},
	}, "subject", "scopes", "ttl_seconds")
	ephemeralAPIKeyPreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"subject": str(), "scopes": {Type: "array", Items: str()},
		"requested_ttl_seconds": {Type: "integer"}, "effective_ttl_seconds": {Type: "integer"},
		"minimum_ttl_seconds": {Type: "integer"}, "maximum_ttl_seconds": {Type: "integer"},
		"required_permission": str(), "request_fingerprint": str(),
		"blockers": {Type: "array", Items: str()}, "preview_writes": {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()}, "execute_writes": {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()}, "recovery_steps": {Type: "array", Items: str()},
		"verification_steps": {Type: "array", Items: str()}, "cli_argv": {Type: "array", Items: str()},
		"token_data_handling": str(), "native_secret_store_needed": {Type: "boolean"},
	}, "capability", "operation", "ready", "effect_free", "subject", "scopes", "requested_ttl_seconds",
		"effective_ttl_seconds", "minimum_ttl_seconds", "maximum_ttl_seconds", "required_permission",
		"request_fingerprint", "blockers", "preview_writes", "preview_external_effects", "execute_writes",
		"execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "token_data_handling",
		"native_secret_store_needed")
	ephemeralAPIKey := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "subject": str(), "scopes": {Type: "array", Items: str()},
		"expires_at": timestamp(), "created_at": timestamp(), "token": str(),
	}, "id", "tenant_id", "subject", "scopes", "expires_at", "created_at", "token")

	auditEvent := object(map[string]*Schema{
		"sequence": {Type: "integer"}, "id": str(), "type": str(),
		"tenant_id": uuid(), "time": timestamp(), "actor": {Type: "object"}, "data": {Type: "object"}, "hash": str(),
	}, "sequence", "type", "tenant_id", "time")
	auditEventList := object(map[string]*Schema{
		"events": {Type: "array", Items: ref("AuditEvent")},
		"count":  {Type: "integer"},
	}, "events")
	auditTimestampInfo := object(map[string]*Schema{
		"version": {Type: "integer"}, "policy": str(), "hash_algorithm": str(),
		"hashed_message": {Type: "string", Format: "byte"}, "serial_number": {Type: "integer"},
		"gen_time": timestamp(),
	}, "version", "policy", "hash_algorithm", "hashed_message", "serial_number", "gen_time")
	auditTimestampToken := object(map[string]*Schema{
		"info": ref("AuditTimestampInfo"), "signature": {Type: "string", Format: "byte"},
		"tsa_cert": {Type: "string", Format: "byte"}, "der": {Type: "string", Format: "byte"},
	}, "info", "signature", "tsa_cert", "der")
	auditAnchorKind := str()
	auditAnchorKind.Enum = []string{"", "rfc3161"}
	auditAnchor := object(map[string]*Schema{
		"kind": auditAnchorKind, "chain_head": str(), "anchored_at": timestamp(),
		"token": ref("AuditTimestampToken"), "detail": str(),
	}, "kind", "chain_head", "anchored_at")
	auditBundle := object(map[string]*Schema{
		"schema_version": {Type: "integer"},
		"format":         {Type: "string", Enum: []string{"jws"}},
		"bundle":         str(), // a compact JWS whose payload is the signed evidence bundle
		"chain_head":     str(),
		"anchor":         ref("AuditAnchor"),
	}, "schema_version", "format", "bundle", "chain_head", "anchor")
	auditVerificationKey := object(map[string]*Schema{
		"kty": str(), "kid": str(), "n": str(), "e": str(),
	}, "kty", "kid", "n", "e")
	auditVerificationKeySet := object(map[string]*Schema{
		"keys": {Type: "array", Items: auditVerificationKey},
	}, "keys")
	auditFeedRequest := object(map[string]*Schema{
		"name":         str(),
		"provider":     {Type: "string", Enum: []string{"splunk-hec", "sentinel"}},
		"endpoint_url": str(), "token_ref": str(),
		"interval_seconds": {Type: "integer"}, "batch_size": {Type: "integer"},
		"enabled": {Type: "boolean"}, "allow_private_endpoint": {Type: "boolean"},
		"private_egress_cidrs": {Type: "array", Items: str()},
	}, "name", "provider", "endpoint_url", "token_ref", "interval_seconds", "batch_size", "enabled")
	auditFeed := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(),
		"provider":     {Type: "string", Enum: []string{"splunk-hec", "sentinel"}},
		"endpoint_url": str(), "token_ref": str(),
		"interval_seconds": {Type: "integer"}, "batch_size": {Type: "integer"},
		"enabled": {Type: "boolean"}, "allow_private_endpoint": {Type: "boolean"},
		"private_egress_cidrs": {Type: "array", Items: str()},
		"status":               {Type: "string", Enum: []string{"not_started", "queued", "delivering", "retrying", "delivered", "failed"}},
		"last_batch_id":        uuid(), "last_batch_start_sequence": {Type: "integer"},
		"last_queued_sequence": {Type: "integer"}, "last_delivered_sequence": {Type: "integer"},
		"last_batch_record_count": {Type: "integer"}, "lag_records": {Type: "integer"},
		"attempts": {Type: "integer"}, "last_error_code": str(), "collector_request_id": str(),
		"next_run_at": timestamp(), "next_attempt_at": timestamp(), "last_attempt_at": timestamp(),
		"last_delivered_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "name", "provider", "endpoint_url", "token_ref", "interval_seconds",
		"batch_size", "enabled", "allow_private_endpoint", "private_egress_cidrs", "status",
		"last_batch_start_sequence", "last_queued_sequence", "last_delivered_sequence",
		"last_batch_record_count", "lag_records", "attempts", "next_run_at", "updated_at")
	auditFeedPreview := object(map[string]*Schema{
		"capability":                 str(),
		"ready":                      {Type: "boolean"},
		"effect_free":                {Type: "boolean"},
		"feed_id":                    uuid(),
		"endpoint_host":              str(),
		"existing_configuration":     {Type: "boolean"},
		"current_updated_at":         timestamp(),
		"request_fingerprint":        str(),
		"required_permission":        str(),
		"normalized_request":         ref("AuditFeedRequest"),
		"prerequisites":              {Type: "array", Items: str()},
		"preview_writes":             {Type: "array", Items: str()},
		"preview_external_effects":   {Type: "array", Items: str()},
		"execution_writes":           {Type: "array", Items: str()},
		"execution_external_effects": {Type: "array", Items: str()},
		"verification_steps":         {Type: "array", Items: str()},
		"recovery_steps":             {Type: "array", Items: str()},
		"warnings":                   {Type: "array", Items: str()},
		"guidance":                   str(),
	}, "capability", "ready", "effect_free", "feed_id", "endpoint_host", "existing_configuration",
		"request_fingerprint", "required_permission", "normalized_request", "prerequisites",
		"preview_writes", "preview_external_effects", "execution_writes", "execution_external_effects",
		"verification_steps", "recovery_steps", "warnings", "guidance")
	auditFeedList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("AuditFeed")},
		"count": {Type: "integer"},
	}, "items")
	custodyOriginCounts := object(map[string]*Schema{
		"requester": {Type: "integer"}, "host_agent": {Type: "integer"},
		"device": {Type: "integer"}, "control_plane": {Type: "integer"}, "signer": {Type: "integer"},
	}, "requester", "host_agent", "device", "control_plane", "signer")
	custodyStorageCounts := object(map[string]*Schema{
		"sealed_store":  {Type: "integer"},
		"locked_memory": {Type: "integer"}, "file": {Type: "integer"}, "os_store": {Type: "integer"},
		"pkcs11": {Type: "integer"}, "device_bound": {Type: "integer"}, "service": {Type: "integer"},
	}, "locked_memory", "file", "os_store", "pkcs11", "device_bound", "service")
	custodyExportabilityCounts := object(map[string]*Schema{
		"exportable": {Type: "integer"}, "non_exportable": {Type: "integer"},
	}, "exportable", "non_exportable")
	unrecordedCustodyCertificate := object(map[string]*Schema{
		"id": uuid(), "fingerprint": str(), "subject": str(),
		"missing_fields": {Type: "array", Items: str()},
	}, "id", "fingerprint", "subject", "missing_fields")
	certificateCustodySummary := object(map[string]*Schema{
		"total": {Type: "integer"}, "recorded": {Type: "integer"}, "unrecorded": {Type: "integer"},
		"origins": ref("CustodyOriginCounts"), "storage": ref("CustodyStorageCounts"),
		"exportability":           ref("CustodyExportabilityCounts"),
		"unrecorded_certificates": {Type: "array", Items: ref("UnrecordedCustodyCertificate")},
	}, "total", "recorded", "unrecorded", "origins", "storage", "exportability", "unrecorded_certificates")
	complianceEvidencePack := object(map[string]*Schema{
		"format":           str(),
		"framework":        {Type: "string", Enum: complianceFrameworkValues()},
		"signed_export":    {Type: "object"},
		"public_key_der":   {Type: "string", Format: "byte"},
		"custody":          ref("CertificateCustodySummary"),
		"adcs":             ref("ADCSComplianceEvidence"),
		"crypto_readiness": ref("CryptoReadiness"),
	}, "format", "framework", "signed_export", "public_key_der", "custody", "adcs", "crypto_readiness")
	complianceReportScheduleReq := object(map[string]*Schema{
		"framework":        {Type: "string", Enum: complianceFrameworkValues()},
		"name":             str(),
		"report_type":      {Type: "string", Enum: []string{"framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"}},
		"interval_seconds": {Type: "integer"},
		"enabled":          {Type: "boolean"},
		"delivery":         {Type: "string", Enum: []string{"audit_export"}},
		"recipient_ref":    str(),
	}, "framework", "name", "report_type", "interval_seconds")
	complianceReportSchedulePreview := object(map[string]*Schema{
		"capability":               str(),
		"operation":                str(),
		"ready":                    {Type: "boolean"},
		"effect_free":              {Type: "boolean"},
		"request_fingerprint":      str(),
		"required_permission":      str(),
		"normalized_request":       ref("ComplianceReportScheduleRequest"),
		"blockers":                 {Type: "array", Items: str()},
		"warnings":                 {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_writes":           {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"secret_data_handling":     str(),
	}, "capability", "operation", "ready", "effect_free", "request_fingerprint", "required_permission", "normalized_request", "blockers", "warnings", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "secret_data_handling")
	complianceReportSchedule := object(map[string]*Schema{
		"id":               uuid(),
		"tenant_id":        uuid(),
		"framework":        {Type: "string", Enum: complianceFrameworkValues()},
		"name":             str(),
		"report_type":      {Type: "string", Enum: []string{"framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"}},
		"interval_seconds": {Type: "integer"},
		"enabled":          {Type: "boolean"},
		"delivery":         {Type: "string", Enum: []string{"audit_export"}},
		"recipient_ref":    str(),
		"next_run_at":      timestamp(),
		"created_at":       timestamp(),
		"updated_at":       timestamp(),
	}, "id", "tenant_id", "framework", "name", "report_type", "interval_seconds", "enabled", "delivery", "next_run_at", "created_at", "updated_at")
	complianceInventorySummary := object(map[string]*Schema{
		"certificates":             {Type: "integer"},
		"crypto_assets":            {Type: "integer"},
		"discovery_schedules":      {Type: "integer"},
		"report_schedules":         {Type: "integer"},
		"enabled_report_schedules": {Type: "integer"},
		"frameworks_supported":     {Type: "integer"},
		"report_types_supported":   {Type: "integer"},
		"inventory_rows":           {Type: "integer"},
	}, "certificates", "crypto_assets", "discovery_schedules", "report_schedules", "enabled_report_schedules", "frameworks_supported", "report_types_supported", "inventory_rows")
	complianceInventoryReport := object(map[string]*Schema{
		"capability":    str(),
		"generated_at":  timestamp(),
		"summary":       ref("ComplianceInventorySummary"),
		"frameworks":    {Type: "array", Items: str()},
		"report_types":  {Type: "array", Items: str()},
		"routes":        {Type: "array", Items: str()},
		"evidence_refs": {Type: "array", Items: str()},
		"schedules":     {Type: "array", Items: ref("ComplianceReportSchedule")},
	}, "capability", "generated_at", "summary", "frameworks", "report_types", "routes", "evidence_refs", "schedules")
	nhiComplianceSummary := object(map[string]*Schema{
		"total_nhis":                  {Type: "integer"},
		"inventory_kinds":             {Type: "integer"},
		"frameworks_supported":        {Type: "integer"},
		"controls_mapped":             {Type: "integer"},
		"overprivileged_findings":     {Type: "integer"},
		"stale_findings":              {Type: "integer"},
		"static_credential_findings":  {Type: "integer"},
		"audit_evidence_refs":         {Type: "integer"},
		"operator_attestation_needed": {Type: "integer"},
	}, "total_nhis", "inventory_kinds", "frameworks_supported", "controls_mapped", "overprivileged_findings", "stale_findings", "static_credential_findings", "audit_evidence_refs", "operator_attestation_needed")
	nhiComplianceFramework := object(map[string]*Schema{
		"id":               {Type: "string", Enum: []string{"nist-800-53", "nist-csf-2.0", "pci-dss-4.0", "dora", "iso-27001", "fedramp", "cmmc-2.0", "eidas", "nis2"}},
		"name":             str(),
		"version":          str(),
		"mapping_status":   {Type: "string", Enum: []string{"served"}},
		"evidence_sources": {Type: "array", Items: str()},
	}, "id", "name", "version", "mapping_status", "evidence_sources")
	nhiComplianceControl := object(map[string]*Schema{
		"framework":       {Type: "string", Enum: []string{"nist-800-53", "nist-csf-2.0", "pci-dss-4.0", "dora", "iso-27001", "fedramp", "cmmc-2.0", "eidas", "nis2"}},
		"control_id":      str(),
		"title":           str(),
		"status":          {Type: "string", Enum: []string{"evidenced", "evidenced_with_operator_attestation"}},
		"evidence_refs":   {Type: "array", Items: str()},
		"posture_signals": {Type: "array", Items: str()},
		"finding_count":   {Type: "integer"},
		"residual":        str(),
	}, "framework", "control_id", "title", "status", "evidence_refs", "posture_signals", "finding_count")
	nhiComplianceReport := object(map[string]*Schema{
		"format":        str(),
		"capability":    str(),
		"generated_at":  timestamp(),
		"audit_ready":   {Type: "boolean"},
		"summary":       ref("NHIComplianceSummary"),
		"frameworks":    {Type: "array", Items: ref("NHIComplianceFramework")},
		"controls":      {Type: "array", Items: ref("NHIComplianceControl")},
		"report_types":  {Type: "array", Items: str()},
		"routes":        {Type: "array", Items: str()},
		"evidence_refs": {Type: "array", Items: str()},
		"residuals":     {Type: "array", Items: str()},
	}, "format", "capability", "generated_at", "audit_ready", "summary", "frameworks", "controls", "report_types", "routes", "evidence_refs", "residuals")
	privacyErasureReq := object(map[string]*Schema{
		"subject": str(),
		"reason":  str(),
	}, "subject")
	privacySubjectErasurePreview := object(map[string]*Schema{
		"capability":               str(),
		"operation":                str(),
		"ready":                    {Type: "boolean"},
		"effect_free":              {Type: "boolean"},
		"request_fingerprint":      str(),
		"required_permission":      str(),
		"normalized_request":       ref("PrivacySubjectErasureRequest"),
		"subject_ref":              str(),
		"counts":                   {Type: "object", AdditionalProperties: &Schema{Type: "integer"}},
		"total_records":            {Type: "integer"},
		"archive_attestations":     {Type: "integer"},
		"active_legal_holds":       {Type: "integer"},
		"prerequisites":            {Type: "array", Items: str()},
		"blockers":                 {Type: "array", Items: str()},
		"warnings":                 {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_writes":           {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"secret_data_handling":     str(),
	}, "capability", "operation", "ready", "effect_free", "request_fingerprint", "required_permission",
		"normalized_request", "subject_ref", "counts", "total_records", "archive_attestations", "active_legal_holds",
		"prerequisites", "blockers", "warnings", "preview_writes", "preview_external_effects", "execute_writes",
		"execute_external_effects", "recovery_steps", "verification_steps", "secret_data_handling")
	privacyErasureSelectors := object(map[string]*Schema{
		"owner_ids":                 {Type: "array", Items: uuid()},
		"identity_ids":              {Type: "array", Items: uuid()},
		"certificate_fingerprints":  {Type: "array", Items: str()},
		"ssh_key_ids":               {Type: "array", Items: uuid()},
		"attestation_ids":           {Type: "array", Items: uuid()},
		"agent_ids":                 {Type: "array", Items: uuid()},
		"agent_offboard_actor_ids":  {Type: "array", Items: uuid()},
		"agent_offboard_reason_ids": {Type: "array", Items: uuid()},
	})
	privacySubjectErasure := object(map[string]*Schema{
		"subject_ref":      str(),
		"requested_by_ref": str(),
		"reason":           str(),
		"selectors":        ref("PrivacyErasureSelectors"),
		"counts":           {Type: "object"},
		"erased_at":        timestamp(),
	}, "subject_ref", "selectors", "counts", "erased_at")
	privacyRetentionCutoffs := object(map[string]*Schema{
		"owner_inactive_before":       timestamp(),
		"identity_terminal_before":    timestamp(),
		"certificate_terminal_before": timestamp(),
		"ssh_stale_before":            timestamp(),
		"access_terminal_before":      timestamp(),
		"approval_actor_before":       timestamp(),
		"profile_actor_before":        timestamp(),
		"attestation_evidence_before": timestamp(),
		"agent_stale_before":          timestamp(),
	}, "owner_inactive_before", "identity_terminal_before", "certificate_terminal_before", "ssh_stale_before", "access_terminal_before", "approval_actor_before", "profile_actor_before", "attestation_evidence_before", "agent_stale_before")
	privacyRetentionRun := object(map[string]*Schema{
		"run_id":           uuid(),
		"requested_by_ref": str(),
		"cutoffs":          ref("PrivacyRetentionCutoffs"),
		"counts":           {Type: "object"},
		"enforced_at":      timestamp(),
	}, "run_id", "cutoffs", "counts", "enforced_at")
	privacyRetentionPreview := object(map[string]*Schema{
		"capability":               str(),
		"operation":                str(),
		"ready":                    {Type: "boolean"},
		"effect_free":              {Type: "boolean"},
		"request_fingerprint":      str(),
		"required_permission":      str(),
		"reviewed_at":              timestamp(),
		"cutoffs":                  ref("PrivacyRetentionCutoffs"),
		"counts":                   {Type: "object", AdditionalProperties: &Schema{Type: "integer"}},
		"total_records":            {Type: "integer"},
		"prerequisites":            {Type: "array", Items: str()},
		"blockers":                 {Type: "array", Items: str()},
		"warnings":                 {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_writes":           {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"secret_data_handling":     str(),
	}, "capability", "operation", "ready", "effect_free", "request_fingerprint", "required_permission",
		"reviewed_at", "cutoffs", "counts", "total_records", "prerequisites", "blockers", "warnings",
		"preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects",
		"recovery_steps", "verification_steps", "secret_data_handling")
	privacyArchiveErasureReq := object(map[string]*Schema{
		"subject":       str(),
		"artifact_type": {Type: "string", Enum: []string{"backup", "signed_audit_archive"}},
		"artifact_uri":  str(),
		"action":        {Type: "string", Enum: []string{"deleted", "legal_hold", "cryptographic_shred"}},
		"reason":        str(),
		"evidence_refs": {Type: "array", Items: str()},
		"held_until":    timestamp(),
	}, "subject", "artifact_type", "action")
	privacyArchiveErasure := object(map[string]*Schema{
		"attestation_id":   uuid(),
		"subject_ref":      str(),
		"requested_by_ref": str(),
		"artifact_type":    {Type: "string", Enum: []string{"backup", "signed_audit_archive"}},
		"artifact_uri":     str(),
		"action":           {Type: "string", Enum: []string{"deleted", "legal_hold", "cryptographic_shred"}},
		"reason":           str(),
		"evidence_refs":    {Type: "array", Items: str()},
		"held_until":       timestamp(),
		"attested_at":      timestamp(),
	}, "attestation_id", "subject_ref", "artifact_type", "action", "evidence_refs", "attested_at")
	privacyCatalogEntry := object(map[string]*Schema{
		"id": str(), "location": str(), "category": str(), "purpose": str(),
		"retention_class": str(), "erasure": str(), "owner": str(),
	}, "id", "location", "category", "purpose", "retention_class", "erasure", "owner")
	privacyCatalog := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("PrivacyCatalogEntry")},
	}, "items")
	privacySubjectExportReq := object(map[string]*Schema{
		"subject": str(),
	}, "subject")
	objArray := func() *Schema { return &Schema{Type: "array", Items: &Schema{Type: "object"}} }
	privacySubjectExport := object(map[string]*Schema{
		"tenant_id":      str(),
		"subject":        str(),
		"subject_ref":    str(),
		"owners":         objArray(),
		"identities":     objArray(),
		"certificates":   objArray(),
		"ssh_keys":       objArray(),
		"attestations":   objArray(),
		"tenant_members": objArray(),
		"api_tokens":     objArray(),
		"approvals":      objArray(),
		"counts":         {Type: "object"},
		"generated_at":   timestamp(),
	}, "tenant_id", "subject", "subject_ref", "counts", "generated_at")
	attestation := object(map[string]*Schema{
		"id":          str(),
		"method":      str(),
		"subject":     str(),
		"selectors":   {Type: "array", Items: str()},
		"claims":      {Type: "object"},
		"verified_at": timestamp(),
	}, "id", "method", "subject", "selectors", "verified_at")
	attestedSVIDReq := object(map[string]*Schema{
		"method":         {Type: "string", Enum: []string{"aws_iid", "azure_imds", "gcp_iit", "github_oidc", "k8s_sat", "tpm"}},
		"payload_base64": str(),
		"public_key_pem": str(),
		"ttl_seconds":    {Type: "integer"},
	}, "method", "payload_base64", "public_key_pem")
	certificateSPIFFEID := &Schema{Type: "string", Format: "uri", Description: "Exact canonical SPIFFE URI read from this certificate, not the friendly attestation subject. Receiving services must verify the certificate chain, validity and revocation and authorize this entire ID. Omitted for pending issuance, missing/noncanonical retained certificate data or an older saved response; never infer an identity from the subject when absent."}
	attestedSVID := object(map[string]*Schema{
		"certificate_pem": str(),
		"spiffe_id":       certificateSPIFFEID,
		"credential_id":   str(),
		"subject":         str(),
		"not_after":       timestamp(),
		"attestation":     ref("Attestation"),
	}, "certificate_pem", "credential_id", "subject", "not_after", "attestation")
	attestedSVIDPreview := object(map[string]*Schema{
		"capability":                 str(),
		"ready":                      {Type: "boolean"},
		"effect_free":                {Type: "boolean"},
		"method":                     str(),
		"requester":                  str(),
		"trust_domain":               str(),
		"supported_methods":          {Type: "array", Items: str()},
		"requested_ttl_seconds":      {Type: "integer"},
		"effective_ttl_seconds":      {Type: "integer"},
		"default_ttl_seconds":        {Type: "integer"},
		"max_ttl_seconds":            {Type: "integer"},
		"ttl_defaulted":              {Type: "boolean"},
		"ttl_clamped":                {Type: "boolean"},
		"required_permission":        str(),
		"attestation_verification":   str(),
		"payload_sha256":             str(),
		"public_key_sha256":          str(),
		"preview_writes":             {Type: "array", Items: str()},
		"preview_external_effects":   {Type: "array", Items: str()},
		"preview_signer_calls":       {Type: "array", Items: str()},
		"execution_writes":           {Type: "array", Items: str()},
		"execution_external_effects": {Type: "array", Items: str()},
		"execution_signer_calls":     {Type: "array", Items: str()},
		"steps":                      {Type: "array", Items: str()},
		"blockers":                   {Type: "array", Items: str()},
		"recovery_steps":             {Type: "array", Items: str()},
		"data_handling":              {Type: "array", Items: str()},
	}, "capability", "ready", "effect_free", "method", "requester", "trust_domain", "supported_methods",
		"requested_ttl_seconds", "effective_ttl_seconds", "default_ttl_seconds", "max_ttl_seconds", "ttl_defaulted", "ttl_clamped",
		"required_permission", "attestation_verification", "payload_sha256", "public_key_sha256",
		"preview_writes", "preview_external_effects", "preview_signer_calls", "execution_writes", "execution_external_effects", "execution_signer_calls",
		"steps", "blockers", "recovery_steps", "data_handling")
	workloadAttesterTrustSourceReq := object(map[string]*Schema{
		"name":                  str(),
		"method":                {Type: "string", Enum: []string{"aws_iid", "azure_imds", "gcp_iit", "github_oidc", "k8s_sat", "tpm"}},
		"issuer":                str(),
		"audience":              str(),
		"jwks":                  {Type: "object"},
		"root_certs_pem":        {Type: "array", Items: str()},
		"expected_nonce_base64": str(),
		"enabled":               {Type: "boolean"},
	}, "name", "method")
	workloadAttesterTrustSourceRotateReq := object(map[string]*Schema{
		"issuer":                str(),
		"audience":              str(),
		"jwks":                  {Type: "object"},
		"root_certs_pem":        {Type: "array", Items: str()},
		"expected_nonce_base64": str(),
		"reason":                str(),
	})
	workloadAttesterTrustSourceRevokeReq := object(map[string]*Schema{
		"reason": str(),
	})
	workloadAttesterTrustSource := object(map[string]*Schema{
		"id":                    uuid(),
		"tenant_id":             uuid(),
		"name":                  str(),
		"method":                {Type: "string", Enum: []string{"aws_iid", "azure_imds", "gcp_iit", "github_oidc", "k8s_sat", "tpm"}},
		"issuer":                str(),
		"audience":              str(),
		"jwks":                  {Type: "object"},
		"root_certs_pem":        {Type: "array", Items: str()},
		"expected_nonce_base64": str(),
		"enabled":               {Type: "boolean"},
		"revoked_at":            timestamp(),
		"revoked_reason":        str(),
		"rotation_version":      {Type: "integer"},
		"last_rotated_at":       timestamp(),
		"created_at":            timestamp(),
		"updated_at":            timestamp(),
	}, "id", "tenant_id", "name", "method", "jwks", "root_certs_pem", "enabled", "rotation_version", "created_at", "updated_at")
	workloadAttesterTrustSourceRotated := object(map[string]*Schema{
		"trust_source": ref("WorkloadAttesterTrustSource"),
	}, "trust_source")
	workloadAttesterTrustSourceRevoked := object(map[string]*Schema{
		"trust_source": ref("WorkloadAttesterTrustSource"),
	}, "trust_source")
	secretSyncWorkloadIdentitySourceReq := object(map[string]*Schema{
		"name":                        str(),
		"provider":                    {Type: "string", Enum: []string{"aws", "gcp", "azure"}},
		"role_arn":                    str(),
		"service_account":             str(),
		"azure_tenant_id":             uuid(),
		"client_id":                   uuid(),
		"target_scope":                str(),
		"audience":                    str(),
		"subject":                     str(),
		"target_id":                   str(),
		"allowed_remote_key_prefixes": {Type: "array", Items: str()},
		"workload_proof_ref":          str(),
		"trust_source_id":             uuid(),
		"enabled":                     {Type: "boolean"},
	}, "name", "audience", "subject", "target_id", "workload_proof_ref", "trust_source_id")
	secretSyncWorkloadIdentitySource := object(map[string]*Schema{
		"id":                          uuid(),
		"tenant_id":                   uuid(),
		"name":                        str(),
		"provider":                    {Type: "string", Enum: []string{"aws", "gcp", "azure"}},
		"role_arn":                    str(),
		"service_account":             str(),
		"azure_tenant_id":             str(),
		"client_id":                   str(),
		"target_scope":                str(),
		"audience":                    str(),
		"subject":                     str(),
		"target_id":                   str(),
		"allowed_remote_key_prefixes": {Type: "array", Items: str()},
		"workload_proof_ref":          str(),
		"trust_source_id":             uuid(),
		"enabled":                     {Type: "boolean"},
		"status":                      {Type: "string", Enum: []string{"ready", "active", "disabled", "offline_disabled", "exchange_failed"}},
		"status_reason":               str(),
		"last_exchange_at":            timestamp(),
		"token_expires_at":            timestamp(),
		"last_failure_at":             timestamp(),
		"created_at":                  timestamp(),
		"updated_at":                  timestamp(),
	}, "id", "tenant_id", "name", "provider", "role_arn", "service_account", "azure_tenant_id", "client_id", "target_scope", "audience", "subject", "target_id", "allowed_remote_key_prefixes", "workload_proof_ref", "trust_source_id", "enabled", "status", "status_reason", "created_at", "updated_at")
	sshStatus := object(map[string]*Schema{
		"served":        {Type: "boolean"},
		"tenant_id":     uuid(),
		"authority_key": str(),
		"krl_version":   {Type: "integer"},
		"revoked_count": {Type: "integer"},
		"attestors":     {Type: "array", Items: str()},
	}, "served", "tenant_id", "krl_version", "revoked_count")
	sshTrustRolloutReq := object(map[string]*Schema{
		"source_id":                uuid(),
		"target_hosts":             {Type: "array", Items: str()},
		"candidate_ca_fingerprint": str(),
		"reload_command":           str(),
		"health_command":           str(),
		"rollback_plan":            str(),
		"status":                   {Type: "string", Enum: []string{"planned", "validating", "health_passed", "rolled_back", "failed"}},
		"confirmed":                {Type: "boolean"},
	}, "target_hosts", "status", "confirmed")
	sshTrustRollout := object(map[string]*Schema{
		"id":                       str(),
		"tenant_id":                uuid(),
		"source_id":                uuid(),
		"target_hosts":             {Type: "array", Items: str()},
		"candidate_ca_fingerprint": str(),
		"reload_command":           str(),
		"health_command":           str(),
		"rollback_plan":            str(),
		"status":                   {Type: "string", Enum: []string{"planned", "validating", "health_passed", "rolled_back", "failed"}},
		"confirmed":                {Type: "boolean"},
		"recorded_at":              timestamp(),
	}, "id", "tenant_id", "target_hosts", "status", "confirmed", "recorded_at")
	sshCertificateReq := object(map[string]*Schema{
		"certificate_type": {Type: "string", Enum: []string{"host", "user"}},
		"public_key":       str(),
		"key_id":           str(),
		"principals":       {Type: "array", Items: str()},
		"ttl_seconds":      {Type: "integer"},
		"critical_options": {Type: "object", AdditionalProperties: str()},
		"extensions":       {Type: "object", AdditionalProperties: str()},
	}, "certificate_type", "public_key", "key_id", "principals")
	sshCertificatePreview := object(map[string]*Schema{
		"capability":                str(),
		"ready":                     {Type: "boolean"},
		"effect_free":               {Type: "boolean"},
		"certificate_type":          {Type: "string", Enum: []string{"host", "user"}},
		"key_id":                    str(),
		"principals":                {Type: "array", Items: str()},
		"requested_ttl_seconds":     {Type: "integer"},
		"effective_ttl_seconds":     {Type: "integer"},
		"ttl_defaulted":             {Type: "boolean"},
		"ttl_clamped":               {Type: "boolean"},
		"public_key_type":           str(),
		"public_key_fingerprint":    str(),
		"authority_fingerprint":     str(),
		"critical_options":          {Type: "object", AdditionalProperties: str()},
		"extensions":                {Type: "object", AdditionalProperties: str()},
		"preview_writes":            {Type: "array", Items: str()},
		"preview_external_effects":  {Type: "array", Items: str()},
		"preview_signer_calls":      {Type: "array", Items: str()},
		"issuance_writes":           {Type: "array", Items: str()},
		"issuance_external_effects": {Type: "array", Items: str()},
		"issuance_signer_calls":     {Type: "array", Items: str()},
		"blockers":                  {Type: "array", Items: str()},
		"recovery_steps":            {Type: "array", Items: str()},
		"secret_data_handling":      {Type: "array", Items: str()},
	}, "capability", "ready", "effect_free", "certificate_type", "key_id", "principals", "requested_ttl_seconds",
		"effective_ttl_seconds", "ttl_defaulted", "ttl_clamped", "public_key_type", "public_key_fingerprint", "authority_fingerprint",
		"critical_options", "extensions", "preview_writes", "preview_external_effects", "preview_signer_calls", "issuance_writes",
		"issuance_external_effects", "issuance_signer_calls", "blockers", "recovery_steps", "secret_data_handling")
	sshCertificate := object(map[string]*Schema{
		"certificate":           str(),
		"certificate_type":      {Type: "string", Enum: []string{"host", "user"}},
		"serial":                {Type: "integer"},
		"key_id":                str(),
		"principals":            {Type: "array", Items: str()},
		"valid_before":          timestamp(),
		"critical_options":      {Type: "object", AdditionalProperties: str()},
		"extensions":            {Type: "object", AdditionalProperties: str()},
		"authority_fingerprint": str(),
		"krl_version":           {Type: "integer"},
	}, "certificate", "certificate_type", "serial", "key_id", "principals", "valid_before", "critical_options", "extensions", "authority_fingerprint", "krl_version")
	sshAttestedUserCertReq := object(map[string]*Schema{
		"method":           {Type: "string", Enum: []string{"aws_iid", "azure_imds", "gcp_iit", "github_oidc", "k8s_sat", "tpm"}},
		"payload_base64":   str(),
		"public_key":       str(),
		"key_id":           str(),
		"ttl_seconds":      {Type: "integer"},
		"approver":         str(),
		"principals":       {Type: "array", Items: str()},
		"source_addresses": {Type: "array", Items: str()},
		"force_command":    str(),
	}, "method", "payload_base64", "public_key", "approver")
	sshAttestedUserCertPreview := object(map[string]*Schema{
		"capability":                 str(),
		"ready":                      {Type: "boolean"},
		"effect_free":                {Type: "boolean"},
		"method":                     str(),
		"supported_methods":          {Type: "array", Items: str()},
		"key_id":                     str(),
		"approver":                   str(),
		"principals":                 {Type: "array", Items: str()},
		"source_addresses":           {Type: "array", Items: str()},
		"force_command":              str(),
		"requested_ttl_seconds":      {Type: "integer"},
		"effective_ttl_seconds":      {Type: "integer"},
		"ttl_defaulted":              {Type: "boolean"},
		"ttl_clamped":                {Type: "boolean"},
		"public_key_type":            str(),
		"public_key_fingerprint":     str(),
		"authority_fingerprint":      str(),
		"required_permission":        str(),
		"attestation_verification":   {Type: "string", Enum: []string{"execution_only"}},
		"payload_sha256":             str(),
		"preview_writes":             {Type: "array", Items: str()},
		"preview_external_effects":   {Type: "array", Items: str()},
		"preview_signer_calls":       {Type: "array", Items: str()},
		"execution_writes":           {Type: "array", Items: str()},
		"execution_external_effects": {Type: "array", Items: str()},
		"execution_signer_calls":     {Type: "array", Items: str()},
		"blockers":                   {Type: "array", Items: str()},
		"recovery_steps":             {Type: "array", Items: str()},
		"data_handling":              {Type: "array", Items: str()},
	}, "capability", "ready", "effect_free", "method", "supported_methods", "key_id", "approver", "principals", "source_addresses",
		"force_command", "requested_ttl_seconds", "effective_ttl_seconds", "ttl_defaulted", "ttl_clamped", "public_key_type",
		"public_key_fingerprint", "authority_fingerprint", "required_permission", "attestation_verification", "payload_sha256",
		"preview_writes", "preview_external_effects", "preview_signer_calls", "execution_writes", "execution_external_effects",
		"execution_signer_calls", "blockers", "recovery_steps", "data_handling")
	sshAttestedUserCert := object(map[string]*Schema{
		"certificate":      str(),
		"serial":           {Type: "integer"},
		"key_id":           str(),
		"subject":          str(),
		"principals":       {Type: "array", Items: str()},
		"valid_before":     timestamp(),
		"approver":         str(),
		"source_addresses": {Type: "array", Items: str()},
		"force_command":    str(),
		"attestation":      ref("Attestation"),
	}, "certificate", "serial", "key_id", "subject", "principals", "valid_before", "approver", "attestation")
	sshRevokeCertReq := object(map[string]*Schema{
		"serial": {Type: "integer"},
		"key_id": str(),
		"reason": str(),
	})
	sshHostRetireReq := object(map[string]*Schema{
		"host":        str(),
		"source_id":   uuid(),
		"run_id":      uuid(),
		"identity_id": uuid(),
		"reason":      str(),
	}, "host")
	sshHostRetirement := object(map[string]*Schema{
		"id":          str(),
		"tenant_id":   uuid(),
		"host":        str(),
		"source_id":   uuid(),
		"run_id":      uuid(),
		"identity_id": uuid(),
		"reason":      str(),
		"status":      {Type: "string", Enum: []string{"retired"}},
		"recorded_at": timestamp(),
	}, "id", "tenant_id", "host", "status", "recorded_at")
	brokerAgentIdentityReq := object(map[string]*Schema{
		"agent_id":       str(),
		"method":         str(),
		"payload_base64": str(),
		"public_key_pem": str(),
		"scopes":         {Type: "array", Items: str()},
		"ttl_seconds":    {Type: "integer"},
		// B-7: optional AGID-05 task envelope binding the credential to one
		// authorized task. Present-but-unverifiable is refused, never ignored.
		"task_envelope_base64": str(),
	}, "agent_id", "method", "payload_base64", "public_key_pem", "scopes")
	// Broker review uses the same effect-free lifetime/proof vocabulary as
	// attested issuance, plus exact scope policy and optional task-gate state.
	brokerPreviewProperties := make(map[string]*Schema, len(attestedSVIDPreview.Properties)+5)
	for name, property := range attestedSVIDPreview.Properties {
		brokerPreviewProperties[name] = property
	}
	brokerPreviewProperties["agent_id"] = str()
	brokerPreviewProperties["scopes"] = &Schema{Type: "array", Items: str()}
	brokerPreviewProperties["policy_evaluation"] = str()
	brokerPreviewProperties["task_envelope_verification"] = str()
	brokerPreviewProperties["task_envelope_sha256"] = str()
	brokerPreviewRequired := append([]string(nil), attestedSVIDPreview.Required...)
	brokerPreviewRequired = append(brokerPreviewRequired, "agent_id", "scopes", "policy_evaluation", "task_envelope_verification", "task_envelope_sha256")
	brokerAgentIdentityPreview := object(brokerPreviewProperties, brokerPreviewRequired...)
	brokerIssuanceFacts := object(map[string]*Schema{
		"agent_id": str(), "subject": str(), "method": str(), "owner_id": uuid(),
		"scopes": {Type: "array", Items: str()}, "task_envelope_digest": str(),
		"requested_ttl_seconds": {Type: "integer"}, "effective_ttl_seconds": {Type: "integer"},
	}, "agent_id", "subject", "method", "owner_id", "scopes", "requested_ttl_seconds", "effective_ttl_seconds")
	brokerProjectionState := &Schema{Type: "string", Enum: []string{"current", "catching_up", "blocked", "unknown"}, Description: "Coarse projection freshness; no cross-tenant counts or error details are disclosed."}
	brokerIdentityHistory := object(map[string]*Schema{
		"certificate_id": uuid(), "fingerprint": str(), "certificate_subject": str(), "serial": str(), "current_owner_id": uuid(),
		"spiffe_id":  certificateSPIFFEID,
		"not_before": timestamp(), "not_after": timestamp(), "recorded_at": timestamp(), "lifecycle_status": str(),
		"state": {Type: "string", Enum: store.BrokerCertificateStates()}, "state_reason": str(),
		"metadata_state": {Type: "string", Enum: []string{"recorded", "unavailable"}, Description: "Unavailable means original facts were not recorded or were removed by privacy policy; never inferred from a current request or owner."},
		"issuance":       ref("BrokerIssuanceFacts"), "generated_at": timestamp(), "projection_state": brokerProjectionState,
	}, "certificate_id", "fingerprint", "certificate_subject", "serial", "recorded_at", "lifecycle_status", "state", "state_reason", "metadata_state", "generated_at", "projection_state")
	brokerIdentityHistoryList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("BrokerAgentIdentityHistory")}, "next_cursor": str(), "generated_at": timestamp(),
		"projection_state": brokerProjectionState, "history_scope": {Type: "string", Enum: []string{"broker_issued_certificates"}, Description: "Issued certificates only, not a complete refusal/failed-attempt feed. Use tenant audit evidence for attempts."},
	}, "items", "next_cursor", "generated_at", "projection_state", "history_scope")
	brokerAgentIdentity := object(map[string]*Schema{
		"agent_id":        str(),
		"node_id":         str(),
		"subject":         str(),
		"credential_id":   str(),
		"certificate_id":  uuid(),
		"certificate_pem": str(),
		"spiffe_id":       certificateSPIFFEID,
		"scopes":          {Type: "array", Items: str()},
		"not_after":       timestamp(),
		"attestation":     ref("Attestation"),
		// B-7: the digest of the verified task envelope this credential binds;
		// absent when the caller supplied none.
		"task_envelope_digest": str(),
	}, "agent_id", "node_id", "subject", "credential_id", "certificate_id", "certificate_pem", "scopes", "not_after", "attestation")
	ephemeralCredentialReq := object(map[string]*Schema{
		"request_id":     str(),
		"method":         str(),
		"payload_base64": str(),
		"public_key_pem": str(),
		"ttl_seconds":    {Type: "integer"},
	}, "request_id", "method", "payload_base64", "public_key_pem")
	stringList := func() *Schema { return &Schema{Type: "array", Items: str()} }
	ephemeralCredentialPreview := object(map[string]*Schema{
		"capability":                  str(),
		"ready":                       {Type: "boolean"},
		"effect_free":                 {Type: "boolean"},
		"request_id":                  str(),
		"method":                      str(),
		"requester":                   str(),
		"trust_domain":                str(),
		"supported_methods":           stringList(),
		"requested_ttl_seconds":       {Type: "integer"},
		"effective_ttl_seconds":       {Type: "integer"},
		"default_ttl_seconds":         {Type: "integer"},
		"max_ttl_seconds":             {Type: "integer"},
		"ttl_defaulted":               {Type: "boolean"},
		"ttl_clamped":                 {Type: "boolean"},
		"approval_required":           {Type: "boolean"},
		"required_approvals":          {Type: "integer"},
		"approval_ttl_seconds":        {Type: "integer"},
		"request_permission":          str(),
		"approval_permission":         str(),
		"attestation_verification":    str(),
		"payload_sha256":              str(),
		"public_key_sha256":           str(),
		"preview_writes":              stringList(),
		"preview_external_effects":    stringList(),
		"preview_signer_calls":        stringList(),
		"submission_writes":           stringList(),
		"submission_external_effects": stringList(),
		"submission_signer_calls":     stringList(),
		"issuance_writes":             stringList(),
		"issuance_external_effects":   stringList(),
		"issuance_signer_calls":       stringList(),
		"steps":                       stringList(),
		"blockers":                    stringList(),
		"recovery_steps":              stringList(),
		"data_handling":               stringList(),
	}, "capability", "ready", "effect_free", "request_id", "method", "requester", "trust_domain", "supported_methods",
		"requested_ttl_seconds", "effective_ttl_seconds", "default_ttl_seconds", "max_ttl_seconds", "ttl_defaulted", "ttl_clamped",
		"approval_required", "required_approvals", "approval_ttl_seconds", "request_permission", "approval_permission", "attestation_verification",
		"payload_sha256", "public_key_sha256", "preview_writes", "preview_external_effects", "preview_signer_calls", "submission_writes",
		"submission_external_effects", "submission_signer_calls", "issuance_writes", "issuance_external_effects", "issuance_signer_calls",
		"steps", "blockers", "recovery_steps", "data_handling")
	ephemeralCredential := object(map[string]*Schema{
		"state":               {Type: "string", Enum: []string{EphemeralStateAwaitingApproval, EphemeralStateIssued}},
		"request_id":          str(),
		"approval_request_id": uuid(),
		"intent_digest":       str(),
		"subject":             str(),
		"credential_id":       str(),
		"certificate_id":      uuid(),
		"certificate_pem":     str(),
		"spiffe_id":           certificateSPIFFEID,
		"required_approvals":  {Type: "integer"},
		"approvals":           {Type: "integer"},
		"expires_at":          timestamp(),
		"not_after":           timestamp(),
		"attestation":         ref("Attestation"),
	}, "state", "request_id", "approval_request_id", "intent_digest", "subject", "required_approvals", "approvals", "expires_at", "attestation")
	ephemeralApprovalReq := object(map[string]*Schema{
		"action":     {Type: "string", Enum: []string{"issue"}},
		"request_id": uuid(), "intent_digest": str(),
	}, "action", "request_id", "intent_digest")
	ephemeralApproval := object(map[string]*Schema{
		"id": uuid(), "intent_digest": str(), "resource": str(),
		"action":   {Type: "string", Enum: []string{"issue"}},
		"approver": str(), "approvals": {Type: "integer"},
		"approval_count": {Type: "integer"}, "required_approvals": {Type: "integer"},
		"status": {Type: "string", Enum: operationApprovalStatuses},
	}, "id", "intent_digest", "resource", "action", "approver", "approvals", "approval_count", "required_approvals", "status")
	pamSessionReq := object(map[string]*Schema{
		"target_type":    {Type: "string", Enum: []string{"postgres", "ssh"}},
		"target_id":      str(),
		"role":           str(),
		"reason":         str(),
		"method":         str(),
		"payload_base64": str(),
		"ttl_seconds":    {Type: "integer"},
		"ssh_public_key": str(),
		"ssh_principal":  str(),
	}, "target_type", "target_id", "role", "method", "payload_base64")
	pamPostgresCredential := object(map[string]*Schema{
		"username": str(), "dsn": str(),
	}, "username", "dsn")
	pamSSHCredential := object(map[string]*Schema{
		"certificate": str(), "principal": str(), "key_id": str(),
		"serial": {Type: "integer"}, "valid_before": timestamp(),
	}, "certificate", "principal", "key_id", "serial", "valid_before")
	pamSession := object(map[string]*Schema{
		"id": uuid(), "target_id": str(), "target_type": str(), "role": str(),
		"status": str(), "subject": str(), "requested_by": str(), "reason": str(),
		"started_at": timestamp(), "expires_at": timestamp(), "ended_at": timestamp(),
		"attestation": ref("Attestation"), "postgres": ref("PAMPostgresCredential"),
		"ssh": ref("PAMSSHCredential"), "audit": {Type: "object"},
	}, "id", "target_id", "target_type", "role", "status", "subject", "requested_by", "started_at", "expires_at", "attestation")
	graphNode := object(map[string]*Schema{
		"id": str(), "kind": str(), "name": str(), "attrs": {Type: "object"},
	}, "id", "kind", "name")
	graphEdge := object(map[string]*Schema{
		"from": str(), "to": str(), "type": str(), "source": str(), "confidence": str(),
	}, "from", "to", "type")
	graphEvidencePath := object(map[string]*Schema{
		"target": ref("GraphNode"),
		"nodes":  {Type: "array", Items: ref("GraphNode")},
		"edges":  {Type: "array", Items: ref("GraphEdge")},
	}, "target", "nodes", "edges")
	graphResponse := object(map[string]*Schema{
		"nodes": {Type: "array", Items: ref("GraphNode")},
		"edges": {Type: "array", Items: ref("GraphEdge")},
	}, "nodes", "edges")
	graphReachable := object(map[string]*Schema{
		"from":  str(),
		"nodes": {Type: "array", Items: ref("GraphNode")},
		"paths": {Type: "array", Items: ref("GraphEvidencePath")},
	}, "from", "nodes", "paths")
	// I1: managed identities whose ownership cannot answer an incident question.
	unownedIdentity := object(map[string]*Schema{
		"identity_id": str(), "name": str(), "status": str(),
		"reason": {Type: "string", Enum: []string{
			"no_owner", "owner_missing_application_model", "ownership_never_attested", "ownership_attestation_stale",
		}},
		"detail": str(),
	}, "identity_id", "name", "reason")
	unownedQueue := object(map[string]*Schema{
		"items":  {Type: "array", Items: ref("UnownedIdentity")},
		"counts": {Type: "object"},
		"total":  {Type: "integer"}, "guidance": str(),
	}, "items", "counts", "total", "guidance")
	// H4: what blocks a CA key's destruction.
	retirementDependent := object(map[string]*Schema{
		"kind": str(), "ref": str(), "detail": str(),
	}, "kind", "ref")
	retirementChecklist := object(map[string]*Schema{
		"key_id": str(), "blocked": {Type: "boolean"},
		"outstanding": {Type: "array", Items: ref("RetirementDependent")},
		"accounted":   {Type: "integer"}, "total": {Type: "integer"},
		"destruction_record": str(), "retirement_status": str(),
		"refusal_record": str(), "guidance": str(),
	}, "key_id", "blocked", "outstanding", "accounted", "total", "guidance")
	// H2: read-only migration assessment.
	migrationAssessRequest := object(map[string]*Schema{
		"plan_id": str(),
		"waves": {Type: "array", Items: object(map[string]*Schema{
			"id": str(), "ordinal": {Type: "integer"},
			"members": {Type: "array", Items: str()},
		}, "id", "ordinal", "members")},
		"require_full_trust": {Type: "boolean"}, "min_trust_percent": {Type: "integer"},
	}, "waves")
	migrationUnknown := object(map[string]*Schema{
		"member": str(),
		"kind": {Type: "string", Enum: []string{
			"no_trust_store_observed", "no_verification_address", "no_deployment_target",
		}},
		"detail": str(),
	}, "member", "kind", "detail")
	migrationAssessedWave := object(map[string]*Schema{
		"id": str(), "ordinal": {Type: "integer"},
		"members":  {Type: "array", Items: str()},
		"blocked":  {Type: "array", Items: str()},
		"guidance": str(),
	}, "id", "ordinal", "members")
	migrationAssessment := object(map[string]*Schema{
		"plan_id":  str(),
		"waves":    {Type: "array", Items: ref("MigrationAssessedWave")},
		"unknowns": {Type: "array", Items: ref("MigrationUnknown")},
		"members":  {Type: "integer"}, "migratable": {Type: "integer"},
		"guidance": str(),
	}, "plan_id", "waves", "unknowns", "members", "migratable", "guidance")
	migrationRunStartMember := object(map[string]*Schema{
		"identity_id": uuid(), "agent_id": uuid(), "trust_anchor_path": str(),
	}, "identity_id", "agent_id", "trust_anchor_path")
	migrationRunStartWave := object(map[string]*Schema{
		"id": str(), "ordinal": {Type: "integer"},
		"members": {Type: "array", Items: ref("MigrationRunStartMember")},
	}, "id", "ordinal", "members")
	migrationRunStartRequest := object(map[string]*Schema{
		"plan_id": str(), "new_authority_id": uuid(),
		"waves": {Type: "array", Items: ref("MigrationRunStartWave")},
	}, "plan_id", "new_authority_id", "waves")
	migrationMemberBinding := object(map[string]*Schema{
		"issuing_authority_source": {Type: "string", Enum: []string{endpointIssuerPlatform, endpointIssuerPrivate, endpointIssuerExternal}},
		"issuing_authority_id":     str(), "target_id": uuid(), "target_revision": str(), "connector": str(), "target": str(),
		"target_config": {Type: "object"}, "required_agent_id": uuid(),
		"trust_anchor_path": str(), "trust_anchor_pem": {Type: "string", Format: "byte"},
		"trust_anchor_fingerprint": str(), "verify_address": str(), "verify_server_name": str(),
		"subject_common_name": str(), "subject_dns_names": {Type: "array", Items: str()},
		"predecessor_certificate_id": uuid(), "predecessor_fingerprint": str(),
		"successor_fingerprint": str(),
	}, "issuing_authority_id", "target_id", "target_revision", "connector", "target", "target_config", "required_agent_id",
		"trust_anchor_path", "trust_anchor_pem", "trust_anchor_fingerprint", "verify_address",
		"subject_common_name", "subject_dns_names", "predecessor_certificate_id", "predecessor_fingerprint")
	migrationRunMember := object(map[string]*Schema{
		"identity_id": uuid(), "binding": ref("MigrationMemberBinding"),
		"trust_verdict": str(), "successor_verdict": str(),
		"rollback_successor_verdict": str(), "rollback_trust_verdict": str(),
	}, "identity_id", "binding")
	migrationRunWave := object(map[string]*Schema{
		"id": str(), "ordinal": {Type: "integer"}, "phase": str(), "started": {Type: "boolean"}, "halt_reason": str(),
		"members": {Type: "array", Items: ref("MigrationRunMember")},
	}, "id", "ordinal", "members", "phase", "started")
	migrationRun := object(map[string]*Schema{
		"id": uuid(), "plan_id": str(), "status": {Type: "string", Enum: []string{
			"planned", "running", "paused", "halted", "rolling_back", "rolled_back", "complete",
		}},
		"waves":       {Type: "array", Items: ref("MigrationRunWave")},
		"halt_reason": str(), "rollback_wave_id": str(), "rollback_stage": str(), "rollback_attempt": {Type: "integer"}, "pause_reason": str(),
	}, "id", "status", "waves")
	migrationRunActionRequest := object(map[string]*Schema{"reason": str()})
	// H1: who trusts a CA, and where those stores live.
	graphTrustStores := object(map[string]*Schema{
		"issuer":           str(),
		"stores":           {Type: "array", Items: ref("GraphNode")},
		"hosts":            {Type: "array", Items: ref("GraphNode")},
		"candidate_stores": {Type: "array", Items: ref("GraphNode")},
		"candidate_hosts":  {Type: "array", Items: ref("GraphNode")},
		"store_count":      {Type: "integer"}, "host_count": {Type: "integer"},
		"candidate_store_count": {Type: "integer"}, "candidate_host_count": {Type: "integer"},
		"guidance": str(),
	}, "issuer", "stores", "hosts", "store_count", "host_count", "guidance")

	// M2: crypto assets sequenced for migration by observed dependency.
	// `unlocated` is its own count rather than folded into the total: a usage
	// the CBOM could not place has no computable blast radius, and absorbing it
	// into a headline number would read as coverage it does not have.
	cryptoDependent := object(map[string]*Schema{
		"node": ref("GraphNode"), "via": ref("GraphNode"), "edge": str(),
	}, "node", "via", "edge")
	cryptoReadinessAction := object(map[string]*Schema{
		"campaign_id": uuid(), "name": str(), "owner": str(), "deadline": timestamp(),
		"wave": str(), "status": str(), "readiness_status": str(), "disposition": str(),
		"evidence_refs": {Type: "array", Items: str()}, "evidence_digests": {Type: "array", Items: str()},
		"readiness_digest": str(), "stale": {Type: "boolean"},
	}, "campaign_id", "name", "owner", "deadline", "wave", "status", "readiness_status", "disposition", "evidence_refs", "evidence_digests", "readiness_digest", "stale")
	cryptoReadinessRow := object(map[string]*Schema{
		"asset":              ref("GraphNode"),
		"exhibitors":         {Type: "array", Items: ref("GraphNode")},
		"dependents":         {Type: "array", Items: ref("CryptoDependent")},
		"owners":             {Type: "array", Items: str()},
		"quantum_vulnerable": {Type: "boolean"},
		"out_of_policy":      {Type: "boolean"},
		"unlocated":          {Type: "boolean"},
		"recommendation":     str(),
		"actions":            {Type: "array", Items: ref("CryptoReadinessAction")},
	}, "asset", "quantum_vulnerable", "out_of_policy", "unlocated", "recommendation", "actions")
	cryptoReadiness := object(map[string]*Schema{
		"format": str(), "tenant_id": uuid(), "dataset_digest": str(),
		"items":  {Type: "array", Items: ref("CryptoReadinessRow")},
		"urgent": {Type: "integer"}, "unlocated": {Type: "integer"},
		"coverage_guidance": str(),
	}, "format", "tenant_id", "dataset_digest", "items", "urgent", "unlocated", "coverage_guidance")
	cryptoReadinessExport := object(map[string]*Schema{
		"dataset": ref("CryptoReadiness"), "dataset_digest": str(), "csv": str(), "ndjson": str(),
		"signed_export": str(), "public_jwks": {Type: "object", AdditionalProperties: &Schema{}},
	}, "dataset", "dataset_digest", "csv", "ndjson", "signed_export", "public_jwks")

	// I2: what a bulk ownership import did, and what it refused to do. Applied
	// and refused are separate numbers on purpose — one total hides the rows
	// somebody actually needed to look at.
	ownershipConflictSchema := object(map[string]*Schema{
		// id is present when listing the queue and absent on an import response:
		// an import reports what it just decided, and those rows have not been
		// read back. So it is optional, not required.
		"id": uuid(), "owner_id": str(), "field": str(),
		"current_value": str(), "current_source": str(),
		"incoming_value": str(), "incoming_source": str(), "incoming_ref": str(),
		"current_attested": {Type: "boolean"}, "why": str(),
	}, "field", "current_attested")
	ownershipImportResult := object(map[string]*Schema{
		"applied":   {Type: "integer"},
		"unchanged": {Type: "integer"},
		"conflicts": {Type: "array", Items: ref("OwnershipConflict")},
		"detail":    str(), "guidance": str(),
	}, "applied", "unchanged", "conflicts", "detail", "guidance")
	brandSchema := object(map[string]*Schema{
		"product_name": str(), "logo_data_uri": str(), "login_message": str(),
		"token_overrides": {Type: "object"},
		// custom separates "the default because nothing is configured" from
		// "the default because this host has no brand". Both render identically
		// and only one is a misconfiguration.
		"custom": {Type: "boolean"},
	}, "product_name", "custom")
	agentUpgradeCampaignSchema := object(map[string]*Schema{
		"id": uuid(), "target_version": str(),
		// active separates "no campaign has ever run" from "one is running".
		"active": {Type: "boolean"},
		"status": {Type: "string", Enum: []string{"pending", "running", "halted", "paused", "complete"}},
		// halted_at_ring is served alongside current_ring because an operator
		// needs to know where a resume would restart — the halted ring, not the
		// next one.
		"current_ring": str(), "halted_at_ring": str(), "reason": str(),
		// rings carries an "unassigned" key; it is never folded into broad.
		"rings": {Type: "object"}, "versions": {Type: "object"},
		// observe_only separates a campaign that merely gates from one that
		// dispatches agent.upgrade jobs itself (artifacts were published).
		"observe_only": {Type: "boolean"},
		// dispatched_ring / dispatch_round are the live dispatch state.
		"dispatched_ring": str(), "dispatch_round": {Type: "integer"},
		"guidance": str(),
		// observe_only is always serialized but NOT in the required list: the
		// golden ratchet correctly refuses newly-required properties, and a
		// pre-dispatch client that never saw the field must keep validating.
	}, "active", "rings", "versions", "guidance")
	upgradeArtifactSchema := object(map[string]*Schema{
		"os": str(), "arch": str(), "url": str(),
		// sha256 pins the exact bytes; the agent refuses anything else, which
		// is what makes an artifact host a download mirror rather than a
		// trusted party.
		"sha256": str(),
	}, "os", "arch", "url", "sha256")
	agentUpgradeCampaignInput := object(map[string]*Schema{
		"target_version": str(),
		// artifacts turns the campaign from observe-only into one that
		// dispatches: one build per platform. Omitted = observe-only. A named
		// component ref, not an inline object: generated clients get a real
		// type and the contract-drift parser reads a parseable field.
		"artifacts": {Type: "array", Items: ref("UpgradeArtifact")},
	}, "target_version")
	agentRingInput := object(map[string]*Schema{
		"agent_id": uuid(),
		"ring":     {Type: "string", Enum: []string{"canary", "early", "broad", ""}},
	}, "agent_id")
	mdmDeviceSchema := object(map[string]*Schema{
		"mdm": {Type: "string", Enum: []string{"intune", "jamf"}},
		// mdm_device_id is a plain string, not a uuid: it is whatever the MDM
		// assigns, and that is the identifier an admin pastes from their console.
		"mdm_device_id": str(), "device_name": str(), "serial_number": str(),
		"transaction_id": str(), "identity_id": uuid(),
		// unknown is NOT failed — an MDM we could not reach tells us nothing.
		"install_state":  {Type: "string", Enum: []string{"ok", "failed", "unknown"}},
		"install_detail": str(), "observed_at": str(),
		// The offline-renewal check (I5): a SCEP device renews by checking in,
		// so a device the MDM has not seen since its certificate's renewal
		// window opened will silently miss its renewal.
		"renewal_not_after": str(), "renewal_at_risk": {Type: "boolean"}, "renewal_detail": str(),
	}, "mdm", "mdm_device_id", "install_state")
	mdmDeviceListSchema := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("MDMDevice")},
		// failed and unobserved are separate counts: one device reported
		// trouble, the other is one nothing has heard from, and a single
		// "unhealthy" number would merge two different problems.
		"failed": {Type: "integer"}, "unobserved": {Type: "integer"},
		// at-risk is counted apart from failed: nothing failed yet, and that
		// is exactly the problem.
		"renewal_at_risk": {Type: "integer"}, "guidance": str(),
	}, "items", "failed", "unobserved", "guidance")
	mdmPollScheduleSchema := object(map[string]*Schema{
		"configured": {Type: "boolean"},
		"mdm":        {Type: "string", Enum: []string{"intune", "jamf"}},
		"base_url":   str(), "token_ref": str(), "filter": str(),
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		"execution":           {Type: "string", Enum: []string{"relay", ""}},
		"renewal_window_days": {Type: "integer"},
		"last_run_at":         str(), "last_error": str(), "guidance": str(),
	}, "configured", "enabled", "guidance")
	mdmPollScheduleInput := object(map[string]*Schema{
		"mdm":      {Type: "string", Enum: []string{"intune", "jamf"}},
		"base_url": str(), "token_ref": str(), "filter": str(),
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		"execution":           {Type: "string", Enum: []string{"relay", ""}},
		"renewal_window_days": {Type: "integer"},
	}, "mdm", "base_url", "token_ref", "interval_seconds")
	mdmPollScheduleList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("MDMPollSchedule")},
		"guidance": str(),
	}, "items", "guidance")
	edgeSegmentPolicySchema := object(map[string]*Schema{
		"segment_id": str(), "segment_name": str(),
		"enabled":               {Type: "boolean"},
		"attestation_roots":     {Type: "integer"},
		"permitted_dns_domains": {Type: "array", Items: str()},
		"excluded_dns_domains":  {Type: "array", Items: str()},
		"allowed_key_providers": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"tpm2", "pkcs11", "software"}}},
		"updated_at":            {Type: "string", Format: "date-time"},
	}, "segment_id", "enabled", "attestation_roots", "allowed_key_providers", "updated_at")
	edgeSegmentPolicyInput := object(map[string]*Schema{
		"segment_id":            str(),
		"enabled":               {Type: "boolean"},
		"attestation_roots_pem": {Type: "array", Items: str()},
		"permitted_dns_domains": {Type: "array", Items: str()},
		"excluded_dns_domains":  {Type: "array", Items: str()},
		"allowed_key_providers": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"tpm2", "pkcs11", "software"}}},
	}, "enabled")
	edgeDelegationSchema := object(map[string]*Schema{
		"id": str(), "segment_id": str(), "ca_id": str(), "host": str(),
		"common_name": str(), "serial": str(), "certificate_pem": str(),
		"permitted_dns_domains": {Type: "array", Items: str()},
		"excluded_dns_domains":  {Type: "array", Items: str()},
		"attested_key_sha256":   str(),
		"csr_key_sha256":        str(),
		"key_provider":          {Type: "string", Enum: []string{"tpm2", "pkcs11", "software"}},
		"key_storage":           {Type: "string", Enum: []string{"device_bound", "pkcs11", "file"}},
		"key_exportable":        {Type: "boolean"},
		"custody_assurance":     {Type: "string", Enum: []string{"hardware_key_attested", "host_attested_operator_claim", "host_attested_software_exception"}},
		"status":                {Type: "string", Enum: []string{"active", "revoked", "expired"}},
		"not_before":            {Type: "string", Format: "date-time"},
		"not_after":             {Type: "string", Format: "date-time"},
		"revoked_at":            {Type: "string", Format: "date-time"},
		"revoke_reason":         str(),
	}, "id", "segment_id", "ca_id", "host", "common_name", "serial", "permitted_dns_domains", "csr_key_sha256", "key_provider", "key_storage", "key_exportable", "custody_assurance", "status", "not_before", "not_after")
	edgeDelegationMintInput := object(map[string]*Schema{
		"segment_id": str(), "ca_id": str(), "host": str(), "common_name": str(),
		"ttl_seconds":                 {Type: "integer"},
		"csr_der":                     {Type: "string", Format: "byte"},
		"attestation_credential_json": {Type: "string", Format: "byte"},
		"key_provider":                {Type: "string", Enum: []string{"tpm2", "pkcs11", "software"}},
	}, "segment_id", "ca_id", "host", "csr_der", "attestation_credential_json")
	edgeIssuanceSchema := object(map[string]*Schema{
		"serial": str(), "subject": str(),
		"dns_names":          {Type: "array", Items: str()},
		"not_before":         {Type: "string", Format: "date-time"},
		"not_after":          {Type: "string", Format: "date-time"},
		"issued_at":          {Type: "string", Format: "date-time"},
		"reconciled_at":      {Type: "string", Format: "date-time"},
		"within_constraints": {Type: "boolean"},
		"violation":          str(),
	}, "serial", "subject", "not_before", "not_after", "issued_at", "reconciled_at", "within_constraints")
	edgeDelegationDetailSchema := object(map[string]*Schema{
		"delegation": ref("EdgeDelegation"),
		"issuances":  {Type: "array", Items: ref("EdgeIssuance")},
	}, "delegation")
	edgeDelegationRevokeInput := object(map[string]*Schema{
		"reason": str(),
	})
	edgeReconcileInput := object(map[string]*Schema{
		"host":             str(),
		"certificates_pem": {Type: "array", Items: str()},
	}, "certificates_pem")
	edgeReconcileResultSchema := object(map[string]*Schema{
		"reconciled": {Type: "integer"}, "violations": {Type: "integer"},
		"already": {Type: "integer"}, "rejected": {Type: "integer"},
		"guidance": str(),
	}, "reconciled", "violations", "already", "rejected")
	edgeSegmentPolicyList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("EdgeSegmentPolicy")},
		"guidance": str(),
	}, "items", "guidance")
	edgeDelegationList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("EdgeDelegation")},
		"guidance": str(),
	}, "items", "guidance")
	adcsDatabaseSummarySchema := object(map[string]*Schema{
		"ca_config": str(),
		"issued":    {Type: "integer"}, "pending": {Type: "integer"}, "revoked": {Type: "integer"},
		"denied": {Type: "integer"}, "failed": {Type: "integer"}, "unknown": {Type: "integer"},
		"unparsed": {Type: "integer"}, "total": {Type: "integer"},
		"rows_read": {Type: "integer"}, "rows_rejected": {Type: "integer"},
		"source": str(), "last_error": str(), "ingested_at": str(),
	}, "ca_config", "issued", "pending", "revoked", "denied", "failed", "unknown", "unparsed", "total", "rows_read", "rows_rejected")
	adcsDatabaseIngestSchema := object(map[string]*Schema{
		"ca_config": str(),
		"rows":      {Type: "array", Items: &Schema{Type: "object", AdditionalProperties: str()}},
		"source":    str(), "last_error": str(),
	}, "ca_config", "rows")
	adcsDatabaseListSchema := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("ADCSDatabaseSummary")},
		"guidance": str(),
	}, "items", "guidance")
	ticketIntakeSchema := object(map[string]*Schema{
		"configured":   {Type: "boolean"},
		"system":       {Type: "string", Enum: []string{"servicenow", "jira"}},
		"instance_url": str(), "token_ref": str(),
		"sn_table":     {Type: "string", Enum: []string{"incident", "sc_req_item", "sc_request", "change_request"}},
		"jira_project": str(), "query": str(),
		"subject_field": str(), "profile_field": str(),
		"requester_field": str(), "justification_field": str(),
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		"allow_private_endpoint": {Type: "boolean"},
		"private_egress_cidrs":   {Type: "array", Items: str()},
		"last_run_at":            str(), "sweep_id": uuid(), "sweep_started_at": timestamp(), "last_attempt_at": timestamp(),
		"next_cursor": str(), "read_count": {Type: "integer"}, "expected_count": {Type: "integer"},
		"pages_completed": {Type: "integer"}, "coverage_complete": {Type: "boolean"},
		"eligible_count": {Type: "integer"}, "skipped_count": {Type: "integer"},
		"last_error": str(), "guidance": str(),
	}, "configured", "enabled", "read_count", "pages_completed", "coverage_complete", "eligible_count", "skipped_count", "guidance")
	ticketIntakeInput := object(map[string]*Schema{
		"system":       {Type: "string", Enum: []string{"servicenow", "jira"}},
		"instance_url": str(), "token_ref": str(),
		"sn_table":     {Type: "string", Enum: []string{"incident", "sc_req_item", "sc_request", "change_request"}},
		"jira_project": str(), "query": str(),
		"subject_field": str(), "profile_field": str(),
		"requester_field": str(), "justification_field": str(),
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		"allow_private_endpoint": {Type: "boolean"},
		"private_egress_cidrs":   {Type: "array", Items: str()},
	}, "system", "instance_url", "token_ref", "subject_field", "profile_field", "interval_seconds")
	mdmTraceStepSchema := object(map[string]*Schema{
		"stage":   {Type: "string", Enum: []string{"requested", "issued", "installed", "renewing"}},
		"outcome": {Type: "string", Enum: []string{"ok", "failed", "pending", "unknown"}},
		"at":      str(), "detail": str(), "source": str(),
	}, "stage", "outcome")
	mdmDeviceTraceSchema := object(map[string]*Schema{
		"trace": object(map[string]*Schema{
			"device_id": str(), "mdm_device_id": str(), "mdm": str(), "device_name": str(),
			"serial_number": str(), "transaction_id": str(),
			"steps": {Type: "array", Items: ref("MDMTraceStep")},
			// broke_at names the FIRST failed stage; reporting the last would
			// send an operator to the symptom rather than the cause.
			"broke_at": str(), "summary": str(),
		}, "steps", "summary"),
		"guidance": str(),
	}, "trace", "guidance")
	issuanceRequestSchema := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "subject": str(), "owner_id": uuid(), "profile": str(),
		"requester": str(), "justification": str(), "origin": str(), "ticket_ref": str(),
		// status is an enum drawn from issuancerequest.States, the same list the
		// server validates against — a hand-copied second enum drifts, and the
		// one that drifts accepts a state the other rejects.
		"status":     {Type: "string", Enum: append([]string(nil), issuancerequest.States...)},
		"decided_by": str(), "decision_reason": str(), "decided_at": str(),
		"identity_id": uuid(), "issued_by": str(), "issued_at": str(),
		"expires_at": str(), "created_at": str(),
	}, "id", "tenant_id", "subject", "requester", "status", "expires_at", "created_at")
	issuanceRequestInput := object(map[string]*Schema{
		"subject": str(), "owner_id": uuid(), "profile": str(), "csr_pem": str(), "justification": str(),
		"origin": str(), "ticket_ref": str(),
	}, "subject", "owner_id")
	issuanceRequestPreview := object(map[string]*Schema{
		"ready": {Type: "boolean"}, "subject": str(), "owner_id": uuid(),
		"owner_name": str(), "owner_kind": str(), "profile": str(), "profile_name": str(),
		"profile_version": {Type: "integer"}, "requester": str(), "csr_supplied": {Type: "boolean"},
		"key_origin":        {Type: "string", Enum: []string{"requester_csr", "deprecated_control_plane_generation"}},
		"approval_required": {Type: "boolean"}, "approval_permission": str(),
		"issuance_permissions":     {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"submission_effects":       {Type: "array", Items: str()},
		"steps":                    {Type: "array", Items: str()}, "warnings": {Type: "array", Items: str()},
		"blockers": {Type: "array", Items: str()}, "guidance": str(),
	}, "ready", "subject", "owner_id", "requester", "csr_supplied", "key_origin",
		"approval_required", "approval_permission", "issuance_permissions", "preview_writes",
		"preview_external_effects", "submission_effects", "steps", "warnings", "blockers", "guidance")
	issuanceDecisionInput := object(map[string]*Schema{
		"reason": str(), "identity_id": uuid(),
	})
	issuanceRequestListSchema := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("IssuanceRequest")},
		// open is separate from the item count: one number cannot say whether a
		// queue needs attention or is merely long with history.
		"open": {Type: "integer"}, "guidance": str(),
	}, "items", "open", "guidance")
	issuanceRequestPreparation := object(map[string]*Schema{
		"request": ref("IssuanceRequest"), "identity": ref("Identity"),
		"csr_pem": str(), "issue_idempotency_key": str(),
	}, "request", "identity", "issue_idempotency_key")
	cmdbReconcileSchedule := object(map[string]*Schema{
		// configured is separate from enabled: "never set up" and "set up and
		// paused" are different operator states, and one flag merges them.
		"configured": {Type: "boolean"}, "instance_url": str(), "token_ref": str(),
		"ci_query": str(), "allow_private_endpoint": {Type: "boolean"},
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		// Scheduled external reads are relay-only: the control plane commits the
		// intent and ingests a signed observation, but never dials the CMDB.
		"execution": {Type: "string", Enum: []string{"relay", ""}},
		// last_error is served rather than only logged: a sync failing for a week
		// otherwise looks identical to one that found nothing to do.
		"last_run_at": str(), "last_error": str(),
		"sweep_id": uuid(), "sweep_started_at": timestamp(), "last_attempt_at": timestamp(),
		"next_cursor": str(), "read_count": {Type: "integer"}, "expected_count": {Type: "integer"},
		"pages_completed": {Type: "integer"}, "coverage_complete": {Type: "boolean"},
		"coverage_status": {Type: "string", Enum: []string{"not_configured", "paused", "not_started", "in_progress", "failed", "complete"}},
		"removed_count":   {Type: "integer"}, "changed_count": {Type: "integer"},
		"guidance": str(),
	}, "configured", "enabled", "read_count", "pages_completed", "coverage_complete", "coverage_status", "removed_count", "changed_count", "guidance")
	ownershipResolveInput := object(map[string]*Schema{"resolution": str()}, "resolution")
	ownershipConflictList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("OwnershipConflict")},
		"refused":  {Type: "integer"},
		"guidance": str(),
	}, "items", "refused", "guidance")
	graphImpact := object(map[string]*Schema{
		"node":     ref("GraphNode"),
		"affected": {Type: "array", Items: ref("GraphNode")},
		"by_kind":  {Type: "object"},
		"paths":    {Type: "array", Items: ref("GraphEvidencePath")},
	}, "node", "affected", "by_kind", "paths")
	outboxReconciliationConflict := object(map[string]*Schema{
		"id": str(), "tenant_id": uuid(), "source_event_id": str(),
		"source_event_sequence": {Type: "integer"}, "source_event_type": str(),
		"idempotency_key": str(), "existing_outbox_id": {Type: "integer"},
		"existing_destination": str(), "existing_effect_lane": str(),
		"existing_payload_sha256": str(), "existing_required_agent_role": str(),
		"existing_required_agent_id": str(), "candidate_destination": str(),
		"candidate_effect_lane": str(), "candidate_payload_sha256": str(),
		"candidate_required_agent_role": str(), "candidate_required_agent_id": str(),
		"reason": str(), "status": {Type: "string", Enum: []string{"quarantined"}},
		"detected_at": timestamp(),
	}, "id", "tenant_id", "source_event_id", "source_event_sequence", "source_event_type",
		"idempotency_key", "existing_outbox_id", "existing_destination", "existing_effect_lane",
		"existing_payload_sha256", "candidate_destination", "candidate_effect_lane",
		"candidate_payload_sha256", "reason", "status", "detected_at")
	outboxReconciliationConflictList := object(map[string]*Schema{
		"items":    {Type: "array", Items: ref("OutboxReconciliationConflict")},
		"guidance": str(),
	}, "items", "guidance")
	incidentExecution := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "compromised_identity_id": uuid(),
		"replacement_identity_id": uuid(), "connector_delivery_id": uuid(),
		"status": str(), "phase": str(), "reason": str(), "blast_radius": ref("GraphImpact"),
		"revocation_status": str(), "evidence_bundle_format": str(), "evidence_bundle": str(),
		"failed_targets": {Type: "array", Items: str()}, "rollback_refs": {Type: "array", Items: str()},
		"idempotency_key": str(), "created_by": str(), "created_at": timestamp(), "updated_at": timestamp(),
		"replacement_identity": ref("Identity"), "connector_delivery": ref("ConnectorDelivery"),
	}, "id", "tenant_id", "compromised_identity_id", "status", "phase", "blast_radius", "failed_targets", "rollback_refs", "created_at", "updated_at")
	fleetReissuanceRun := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "issuer_id": uuid(),
		"migration_run_id": uuid(), "replacement_authority_id": uuid(),
		"mode":                      {Type: "string", Enum: []string{"legacy", "live", "game_day"}},
		"plan_digest":               str(),
		"exact_trust_store_ids":     {Type: "array", Items: str()},
		"exact_trust_hosts":         {Type: "array", Items: str()},
		"candidate_trust_store_ids": {Type: "array", Items: str()},
		"candidate_trust_hosts":     {Type: "array", Items: str()},
		"status":                    str(), "phase": str(), "reason": str(), "batch_size": {Type: "integer"},
		"batch_count": {Type: "integer"}, "next_batch_index": {Type: "integer"},
		"halted_reason": str(), "connector": str(), "target": str(),
		"graph_impact":             ref("GraphImpact"),
		"affected_identity_ids":    {Type: "array", Items: uuid()},
		"replacement_identity_ids": {Type: "array", Items: uuid()},
		"revoked_identity_ids":     {Type: "array", Items: uuid()},
		"connector_delivery_ids":   {Type: "array", Items: uuid()},
		"batches":                  {Type: "array", Items: ref("FleetReissuanceBatch")},
		"health_gates":             {Type: "array", Items: ref("FleetReissuanceHealthGate")},
		"failed_targets":           {Type: "array", Items: str()},
		"rollback_refs":            {Type: "array", Items: str()},
		"evidence_bundle_format":   str(), "evidence_bundle": str(),
		"idempotency_key": str(), "created_by": str(), "created_at": timestamp(), "updated_at": timestamp(),
		"replacement_identities": {Type: "array", Items: ref("Identity")},
		"connector_deliveries":   {Type: "array", Items: ref("ConnectorDelivery")},
	}, "id", "tenant_id", "issuer_id", "mode", "exact_trust_store_ids", "exact_trust_hosts",
		"candidate_trust_store_ids", "candidate_trust_hosts", "status", "phase", "batch_size",
		"batch_count", "next_batch_index", "graph_impact", "affected_identity_ids",
		"replacement_identity_ids", "revoked_identity_ids", "batches", "health_gates",
		"rollback_refs", "created_at", "updated_at")
	fleetReissuanceEvidence := object(map[string]*Schema{
		"run_id": uuid(), "evidence_bundle_format": str(), "evidence_bundle": str(),
		"rollback_refs":  {Type: "array", Items: str()},
		"failed_targets": {Type: "array", Items: str()},
		"exported_at":    timestamp(),
	}, "run_id", "evidence_bundle_format", "evidence_bundle", "rollback_refs", "exported_at")
	itsmTicket := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "provider": str(), "destination": str(),
		"table": str(), "status": str(), "outbox_id": {Type: "integer"},
		"idempotency_key": str(), "created_at": timestamp(),
	}, "id", "tenant_id", "provider", "destination", "table", "status", "outbox_id", "idempotency_key", "created_at")
	graphQueryResult := object(map[string]*Schema{
		"rows": {Type: "array", Items: &Schema{Type: "object"}},
	}, "rows")

	// Advertised capability is derived from what the agent binary can actually
	// collect (internal/agent/discovery.ShippedSourceKinds), and enable_flags
	// names the flags that switch each source on — a listed source with flags
	// collects nothing until an operator configures it.
	agentDiscoveryCapability := object(map[string]*Schema{
		"enable_flags":      {Type: "array", Items: str()},
		"source_kind":       str(),
		"label":             str(),
		"reported_over":     str(),
		"metadata_only":     {Type: "boolean"},
		"private_key_bytes": {Type: "boolean"},
	}, "source_kind", "label", "reported_over", "metadata_only", "private_key_bytes")
	agentPresence := object(map[string]*Schema{
		"state":        {Type: "string", Enum: []string{"online", "stale", "unreported", "offboarded", "clock_skew"}},
		"online":       {Type: "boolean"},
		"evaluated_at": timestamp(),
		"fresh_until":  timestamp(),
		"detail":       str(),
	}, "state", "online", "evaluated_at", "detail")
	agent := object(map[string]*Schema{
		"id": uuid(), "name": str(), "status": str(), "version": str(), "last_seen_at": timestamp(),
		"presence":      ref("AgentPresence"),
		"offboarded_at": timestamp(), "offboarded_by": str(), "offboard_reason": str(),
		"inventory_report_path":  str(),
		"discovery_capabilities": {Type: "array", Items: ref("AgentDiscoveryCapability")},
		// Capability grant projected from the agent's certificate SANs (epic A2).
		// Not editable: the role lives in a signed SAN, so changing it is a
		// re-enrollment.
		"roles":       {Type: "array", Items: &Schema{Type: "string", Enum: []string{"host", "network"}}},
		"role_source": {Type: "string", Enum: []string{"certificate", "unreported"}},
		// A3: what a relay build executes, derived from the agent's shipped
		// census so the console cannot advertise an executor the binary lacks.
		"relay_capabilities": {Type: "array", Items: ref("AgentRelayCapability")},
		"workload_api":       ref("AgentWorkloadAPIStatus"),
		"enrollment_proxy":   ref("AgentEnrollmentProxyStatus"),
	}, "id", "name", "status", "presence", "inventory_report_path", "discovery_capabilities", "roles", "role_source", "relay_capabilities", "workload_api", "enrollment_proxy")
	// B3: whether this host serves the SPIFFE Workload API for its own workloads.
	agentWorkloadAPIStatus := object(map[string]*Schema{
		"state":        {Type: "string", Enum: []string{"serving", "not_serving", "unreported"}},
		"svids_issued": {Type: "integer"},
		"reported_at":  timestamp(),
		"detail":       str(),
	}, "state", "svids_issued", "detail")
	agentEnrollmentProxyStatus := object(map[string]*Schema{
		"state":               {Type: "string", Enum: []string{"serving", "degraded", "unavailable", "unverified", "not_serving", "unreported"}},
		"segment":             str(),
		"public_url":          str(),
		"healthy_upstreams":   {Type: "integer"},
		"unhealthy_upstreams": {Type: "integer"},
		"unknown_upstreams":   {Type: "integer"},
		"upstream_failures":   {Type: "integer"},
		"forwarded_requests":  {Type: "integer"},
		"refused_requests":    {Type: "integer"},
		"last_forwarded_at":   timestamp(),
		"last_failover_at":    timestamp(),
		"reported_at":         timestamp(),
		"detail":              str(),
	}, "state", "healthy_upstreams", "unhealthy_upstreams", "unknown_upstreams", "upstream_failures", "forwarded_requests", "refused_requests", "detail")
	agentRelayCapability := object(map[string]*Schema{
		"kind":         str(),
		"connectors":   {Type: "array", Items: str()},
		"enable_flags": {Type: "array", Items: str()},
	}, "kind", "connectors")
	agentList := object(map[string]*Schema{
		"agents":      {Type: "array", Items: ref("Agent")},
		"next_cursor": str(),
	}, "agents")
	enrollmentToken := object(map[string]*Schema{
		"token": str(), "enroll_path": str(), "agent_server": str(), "agent_server_name": str(),
		// The effective grant this token carries into the enrolled certificate,
		// after normalization — so an operator sees what they authorized rather
		// than what they typed (epic A2).
		"roles": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"host", "network"}}},
	}, "token", "roles", "agent_server", "agent_server_name")
	enrollmentTokenReq := object(map[string]*Schema{
		"allowed_identity": str(),
		// Capability grant for the enrolled agent. Empty means host-only.
		// Requesting "network" additionally requires the agents:relay.grant
		// permission, because a relay holds the credentials for the appliances it
		// fronts.
		"roles": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"host", "network"}}},
	})
	enrollmentPlanPreview := object(map[string]*Schema{
		"ready":                  {Type: "boolean"},
		"side_effects":           {Type: "boolean"},
		"allowed_identity":       str(),
		"roles":                  {Type: "array", Items: &Schema{Type: "string", Enum: []string{"host", "network"}}},
		"required_permissions":   {Type: "array", Items: str()},
		"enroll_path":            str(),
		"agent_server":           str(),
		"agent_server_name":      str(),
		"renewal_ready":          {Type: "boolean"},
		"renewal_path":           str(),
		"renewal_authentication": str(),
		"data_handling":          str(),
		"blocked_reasons":        {Type: "array", Items: str()},
	}, "ready", "side_effects", "roles", "required_permissions", "enroll_path", "agent_server", "agent_server_name", "renewal_ready", "renewal_path", "renewal_authentication", "data_handling", "blocked_reasons")
	agentCertRevocationReq := object(map[string]*Schema{
		"agent": str(), "serial": str(), "fingerprint": str(), "reason": str(),
	})
	agentCertRevocation := object(map[string]*Schema{
		"agent_id": uuid(), "agent": str(), "serial": str(), "fingerprint": str(),
		"reason": str(), "revoked_at": timestamp(),
	}, "agent_id", "revoked_at")
	agentOffboardReq := object(map[string]*Schema{
		"reason": str(),
	})
	agentOffboardResp := object(map[string]*Schema{
		"agent":               ref("Agent"),
		"revocation_evidence": str(),
	}, "agent", "revocation_evidence")
	riskComponents := object(map[string]*Schema{
		"age": {Type: "number"}, "exposure": {Type: "number"}, "privilege": {Type: "number"},
		"rotation": {Type: "number"}, "owner": {Type: "number"}, "sensitivity": {Type: "number"},
	}, "age", "exposure", "privilege", "rotation", "owner", "sensitivity")
	credentialRisk := object(map[string]*Schema{
		"credential_id": uuid(), "subject": str(), "kind": str(),
		"privilege": {Type: "integer"}, "sensitivity": {Type: "integer"},
		"exposure": {Type: "integer"}, "owner_active": {Type: "boolean"},
		"expires_at": timestamp(), "score": {Type: "number"},
		"components": ref("RiskComponents"),
	}, "credential_id", "subject", "kind", "privilege", "sensitivity", "exposure", "owner_active", "expires_at", "score", "components")
	credentialRiskList := object(map[string]*Schema{
		"credentials": {Type: "array", Items: ref("CredentialRisk")},
	}, "credentials")
	contextualRiskSummary := object(map[string]*Schema{
		"total_analyzed":      {Type: "integer"},
		"priorities":          {Type: "integer"},
		"critical":            {Type: "integer"},
		"high":                {Type: "integer"},
		"medium":              {Type: "integer"},
		"low":                 {Type: "integer"},
		"high_blast_radius":   {Type: "integer"},
		"weak_crypto_context": {Type: "integer"},
		"orphaned":            {Type: "integer"},
		"near_expiry":         {Type: "integer"},
		"recommendations":     {Type: "integer"},
	}, "total_analyzed", "priorities", "critical", "high", "medium", "low", "high_blast_radius", "weak_crypto_context", "orphaned", "near_expiry", "recommendations")
	urgentRiskProjectionSummary := object(map[string]*Schema{
		"analyzed": {Type: "integer"},
		"critical": {Type: "integer"},
		"high":     {Type: "integer"},
	}, "analyzed", "critical", "high")
	urgentRiskSummary := object(map[string]*Schema{
		"status":                {Type: "string", Enum: []string{"complete"}},
		"scope":                 str(),
		"included_projections":  {Type: "array", Items: str()},
		"unique_analyzed":       {Type: "integer"},
		"urgent":                {Type: "integer"},
		"critical":              {Type: "integer"},
		"high":                  {Type: "integer"},
		"credential_risk":       ref("UrgentRiskProjectionSummary"),
		"contextual_priorities": ref("UrgentRiskProjectionSummary"),
	}, "status", "scope", "included_projections", "unique_analyzed", "urgent", "critical", "high", "credential_risk", "contextual_priorities")
	contextualRiskPriority := object(map[string]*Schema{
		"rank":                      {Type: "integer"},
		"credential_id":             uuid(),
		"subject":                   str(),
		"kind":                      str(),
		"severity":                  {Type: "string", Enum: []string{"critical", "high", "medium", "low"}},
		"contextual_score":          {Type: "number"},
		"base_score":                {Type: "number"},
		"blast_radius":              {Type: "integer"},
		"resource_blast_radius":     {Type: "integer"},
		"workload_blast_radius":     {Type: "integer"},
		"credential_blast_radius":   {Type: "integer"},
		"crypto_asset_blast_radius": {Type: "integer"},
		"weak_crypto_context":       {Type: "integer"},
		"privilege":                 {Type: "integer"},
		"sensitivity":               {Type: "integer"},
		"owner_active":              {Type: "boolean"},
		"expires_at":                timestamp(),
		"components":                ref("RiskComponents"),
		"priority_reasons":          {Type: "array", Items: str()},
		"evidence_refs":             {Type: "array", Items: str()},
		"recommended_action":        str(),
	}, "rank", "credential_id", "subject", "kind", "severity", "contextual_score", "base_score", "blast_radius", "resource_blast_radius", "workload_blast_radius", "credential_blast_radius", "crypto_asset_blast_radius", "weak_crypto_context", "privilege", "sensitivity", "owner_active", "expires_at", "components", "priority_reasons", "evidence_refs", "recommended_action")
	contextualRiskPriorities := object(map[string]*Schema{
		"capability":     str(),
		"generated_at":   timestamp(),
		"coverage":       {Type: "array", Items: str()},
		"summary":        ref("ContextualRiskSummary"),
		"urgent_summary": ref("UrgentRiskSummary"),
		"priorities":     {Type: "array", Items: ref("ContextualRiskPriority")},
	}, "capability", "generated_at", "coverage", "summary", "urgent_summary", "priorities")
	cbomScanReq := object(map[string]*Schema{
		"tls_endpoints": {Type: "array", Items: str()},
		"host_configs":  {Type: "array", Items: str()},
	})
	cbomScanPreview := object(map[string]*Schema{
		"capability": {Type: "string"}, "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"normalized_request": ref("CBOMScanRequest"), "source_count": {Type: "integer"},
		"tls_connection_limit": {Type: "integer"}, "host_read_selector_count": {Type: "integer"},
		"host_file_read_limit": {Type: "integer"}, "host_file_byte_limit": {Type: "integer"},
		"finding_write_limit": {Type: "integer"}, "worker_limit": {Type: "integer"},
		"queue_depth": {Type: "integer"}, "per_endpoint_timeout_seconds": {Type: "integer"},
		"outside_calls": {Type: "array", Items: str()}, "host_reads": {Type: "array", Items: str()},
		"durable_writes": {Type: "array", Items: str()}, "signer_calls": {Type: "integer"},
		"outbox_calls": {Type: "integer"}, "blockers": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()}, "safety_notes": {Type: "array", Items: str()},
	}, "capability", "ready", "effect_free", "normalized_request", "source_count", "tls_connection_limit",
		"host_read_selector_count", "host_file_read_limit", "host_file_byte_limit", "finding_write_limit",
		"worker_limit", "queue_depth", "per_endpoint_timeout_seconds", "outside_calls", "host_reads",
		"durable_writes", "signer_calls", "outbox_calls", "blockers", "recovery_steps", "safety_notes")
	cbomReport := object(map[string]*Schema{
		"sources":            {Type: "integer"},
		"findings":           {Type: "integer"},
		"weak":               {Type: "integer"},
		"quantum_vulnerable": {Type: "integer"},
		"out_of_policy":      {Type: "integer"},
		"failed":             {Type: "integer"},
	}, "sources", "findings", "weak", "quantum_vulnerable", "out_of_policy", "failed")
	cbomMigrationProgress := object(map[string]*Schema{
		"total_assets":              {Type: "integer"},
		"quantum_vulnerable_assets": {Type: "integer"},
		"out_of_policy_assets":      {Type: "integer"},
		"post_quantum_ready_assets": {Type: "integer"},
		"percent_migrated":          {Type: "number"},
	}, "total_assets", "quantum_vulnerable_assets", "out_of_policy_assets", "post_quantum_ready_assets", "percent_migrated")
	cbomAsset := object(map[string]*Schema{
		"id": uuid(), "kind": str(), "location": str(), "algorithm": str(),
		"key_bits": {Type: "integer"}, "protocol": str(), "cipher": str(), "library": str(),
		"strength": str(), "quantum_vulnerable": {Type: "boolean"}, "out_of_policy": {Type: "boolean"},
		"reasons": {Type: "array", Items: str()}, "migration_target": str(),
		"migration_standard": str(), "migration_generation": str(),
	}, "id", "kind", "location", "strength", "quantum_vulnerable", "out_of_policy", "migration_target", "migration_standard", "migration_generation")
	cbomInventory := object(map[string]*Schema{
		"items":              {Type: "array", Items: ref("CBOMAsset")},
		"migration_progress": ref("CBOMMigrationProgress"),
	}, "items", "migration_progress")
	cbomScan := object(map[string]*Schema{
		"report":             ref("CBOMReport"),
		"migration_progress": ref("CBOMMigrationProgress"),
	}, "report", "migration_progress")
	acmeDeviceAttestationPolicy := object(map[string]*Schema{
		"enabled":               {Type: "boolean"},
		"format":                {Type: "string", Enum: []string{"tpm"}},
		"attestation_roots_pem": {Type: "array", Items: str()},
		"allowed_identifiers":   {Type: "array", Items: str()},
		"allowed_algorithms":    {Type: "array", Items: &Schema{Type: "integer"}},
		"max_age":               str(),
	})
	certificateProfileSpec := object(map[string]*Schema{
		"name":                    str(),
		"version":                 {Type: "integer"},
		"requires_approval":       {Type: "boolean"},
		"allowed_key_algorithms":  {Type: "array", Items: str()},
		"min_rsa_bits":            {Type: "integer"},
		"min_ecdsa_bits":          {Type: "integer"},
		"allowed_ekus":            {Type: "array", Items: str()},
		"max_validity":            str(),
		"allowed_protocols":       {Type: "array", Items: str()},
		"acme_auth_mode":          {Type: "string", Enum: []string{"public_trust", "trust_authenticated"}},
		"allowed_dns_suffixes":    {Type: "array", Items: str()},
		"allowed_ip_cidrs":        {Type: "array", Items: str()},
		"allowed_email_domains":   {Type: "array", Items: str()},
		"allowed_uri_prefixes":    {Type: "array", Items: str()},
		"acme_device_attestation": ref("ACMEDeviceAttestationPolicy"),
	})
	profile := object(map[string]*Schema{
		"id": uuid(), "name": str(), "version": {Type: "integer"},
		"active": {Type: "boolean"}, "created_by": str(), "spec": ref("CertificateProfileSpec"),
	}, "id", "name", "version")
	profileReq := object(map[string]*Schema{
		"name": str(), "spec": ref("CertificateProfileSpec"),
	}, "name", "spec")
	profileEditApprovalDecision := &Schema{Type: "object", Properties: map[string]*Schema{
		"approver": str(), "decision": {Type: "string", Enum: []string{"approve"}}, "at": timestamp(),
	}, Required: []string{"approver", "decision", "at"}}
	profileEditApprovalRecord := &Schema{Type: "object", Properties: map[string]*Schema{
		"id": uuid(), "kind": {Type: "string", Enum: []string{"profile_edit"}}, "resource": str(), "profile_name": str(),
		"requester": str(), "required_approvals": {Type: "integer"},
		"approvals":  {Type: "array", Items: ref("ProfileEditApprovalDecision")},
		"state":      {Type: "string", Enum: []string{"awaiting_approval", "approved", "issued", "denied", "expired"}},
		"profile_id": uuid(), "created_at": timestamp(), "expires_at": timestamp(),
	}, Required: []string{"id", "kind", "resource", "profile_name", "requester", "required_approvals", "approvals", "state", "created_at", "expires_at"}}
	profileEditApprovalDecisionReq := &Schema{Type: "object", Properties: map[string]*Schema{"reason": str()}}
	profileApproval := object(map[string]*Schema{
		"approval_id": uuid(), "state": str(), "resource": str(),
	}, "approval_id", "state", "resource")
	profileRestoreReq := object(map[string]*Schema{
		"expected_active_version": {Type: "integer"},
		"reason":                  {Type: "string", MinLength: 1, MaxLength: 1000},
	}, "expected_active_version", "reason")
	profileRestorePreview := object(map[string]*Schema{
		"capability":               {Type: "string", Enum: []string{"certificate_profile_recovery"}},
		"operation":                {Type: "string", Enum: []string{"restore_as_new_version"}},
		"ready":                    {Type: "boolean"},
		"name":                     str(),
		"source_version":           {Type: "integer"},
		"active_version":           {Type: "integer"},
		"next_version":             {Type: "integer"},
		"reason":                   str(),
		"source_spec_digest":       str(),
		"request_fingerprint":      str(),
		"required_permission":      str(),
		"changes":                  {Type: "array", Items: str()},
		"risks":                    {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"source_spec":              ref("CertificateProfileSpec"),
	}, "capability", "operation", "ready", "name", "source_version", "active_version", "next_version", "reason", "source_spec_digest", "request_fingerprint", "required_permission", "changes", "risks", "verification_steps", "preview_writes", "preview_external_effects", "source_spec")

	// Served secrets/identity surface (GAP-006). The metadata view never carries a
	// value; the value/share/key views are the only places a secret leaves the
	// boundary, returned solely to the authorized caller (AN-8).
	secretCreateReq := object(map[string]*Schema{
		"name": str(), "owner_id": uuid(), "value": str(),
	}, "name", "value")
	secretStoreCreatePreview := object(map[string]*Schema{
		"capability": {Type: "string", Enum: []string{"F63"}},
		"operation":  {Type: "string", Enum: []string{"create"}},
		"ready":      {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"name": str(), "owner_id": uuid(), "next_version": {Type: "integer"},
		"required_permission": str(), "request_fingerprint": str(),
		"blockers":                 {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_writes":           {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"secret_data_handling":     str(),
	}, "capability", "operation", "ready", "effect_free", "name", "next_version", "required_permission", "request_fingerprint", "blockers", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "secret_data_handling")
	secretAccessPreviewReq := object(map[string]*Schema{
		"name": str(), "env_var": str(), "resolve": {Type: "boolean"},
	}, "name", "env_var", "resolve")
	secretAccessAPIRequest := object(map[string]*Schema{
		"method": {Type: "string", Enum: []string{"GET"}}, "path": str(),
	}, "method", "path")
	secretAccessBulkImport := object(map[string]*Schema{
		"available": {Type: "boolean"}, "reason": str(), "safe_path": str(),
	}, "available", "reason", "safe_path")
	secretAccessPreview := object(map[string]*Schema{
		"capability": {Type: "string", Enum: []string{"F64"}},
		"operation":  {Type: "string", Enum: []string{"read_for_process"}},
		"ready":      {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"name": str(), "version": {Type: "integer"}, "env_var": str(), "resolve_references": {Type: "boolean"},
		"required_permission": str(), "request_fingerprint": str(),
		"blockers":                 {Type: "array", Items: str()},
		"preview_reads":            {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_reads":            {Type: "array", Items: str()},
		"execute_data_flow":        {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"verification_steps":       {Type: "array", Items: str()},
		"cli_argv":                 {Type: "array", Items: str()},
		"api_request":              secretAccessAPIRequest,
		"typescript":               str(),
		"bulk_import":              secretAccessBulkImport,
		"secret_data_handling":     str(),
	}, "capability", "operation", "ready", "effect_free", "name", "env_var", "resolve_references", "required_permission", "request_fingerprint", "blockers", "preview_reads", "preview_writes", "preview_external_effects", "execute_reads", "execute_data_flow", "recovery_steps", "verification_steps", "cli_argv", "api_request", "typescript", "bulk_import", "secret_data_handling")
	secretRotateReq := object(map[string]*Schema{
		"value": str(),
	}, "value")
	secretImportReq := object(map[string]*Schema{
		"prefix": str(), "values": {Type: "object"},
	}, "values")
	secretMeta := object(map[string]*Schema{
		"name": str(), "owner_id": uuid(), "version": {Type: "integer"}, "created_at": timestamp(), "updated_at": timestamp(),
	}, "name", "version")
	dynamicLeaseReq := object(map[string]*Schema{
		"provider": str(), "role": str(), "ttl_seconds": {Type: "integer"}, "preview_fingerprint": str(),
	}, "provider", "role", "ttl_seconds")
	dynamicSecretRequirement := object(map[string]*Schema{
		"key": str(), "label": str(),
		"kind":     {Type: "string", Enum: []string{"tenant", "identifier", "role_allowlist", "duration", "value", "network_policy", "credential_reference", "role_binding"}},
		"required": {Type: "boolean"}, "description": str(),
	}, "key", "label", "kind", "required", "description")
	dynamicSecretSupportedProvider := object(map[string]*Schema{
		"type":  {Type: "string", Enum: []string{"postgresql", "mysql", "mongodb", "aws-iam", "gcp-iam", "azure-entra", "kubernetes", "redis"}},
		"label": str(), "purpose": str(),
		"requirements": {Type: "array", Items: ref("DynamicSecretProviderRequirement")},
	}, "type", "label", "purpose", "requirements")
	dynamicSecretConfiguredProvider := object(map[string]*Schema{
		"id": str(), "type": str(), "label": str(),
		"allowed_roles": {Type: "array", Items: str()}, "maximum_ttl_seconds": {Type: "integer"},
		"ready": {Type: "boolean"}, "configuration_revision": str(),
	}, "id", "type", "label", "allowed_roles", "maximum_ttl_seconds", "ready", "configuration_revision")
	dynamicSecretProviderCatalog := object(map[string]*Schema{
		"capability":                            {Type: "string", Enum: []string{"F65"}},
		"configuration_mode":                    {Type: "string", Enum: []string{"startup_static"}},
		"configuration_changes_require_restart": {Type: "boolean"},
		"secret_delivery":                       {Type: "string", Enum: []string{"file_or_secret_reference"}},
		"supported_providers":                   {Type: "array", Items: ref("DynamicSecretSupportedProvider")},
		"configured_providers":                  {Type: "array", Items: ref("DynamicSecretConfiguredProvider")},
		"blockers":                              {Type: "array", Items: str()}, "documentation_path": str(), "secret_data_handling": str(),
	}, "capability", "configuration_mode", "configuration_changes_require_restart", "secret_delivery", "supported_providers", "configured_providers", "blockers", "documentation_path", "secret_data_handling")
	dynamicLeasePreview := object(map[string]*Schema{
		"capability": {Type: "string", Enum: []string{"F65"}},
		"operation":  {Type: "string", Enum: []string{"issue_dynamic_secret_lease"}},
		"ready":      {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"provider_id": str(), "provider_type": str(), "provider_label": str(), "role": str(),
		"requested_ttl_seconds": {Type: "integer"}, "effective_ttl_seconds": {Type: "integer"}, "maximum_ttl_seconds": {Type: "integer"},
		"configuration_revision": str(), "required_permission": str(), "request_fingerprint": str(),
		"blockers": {Type: "array", Items: str()}, "preview_writes": {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()}, "execute_writes": {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()}, "recovery_steps": {Type: "array", Items: str()},
		"verification_steps": {Type: "array", Items: str()}, "cli_argv": {Type: "array", Items: str()}, "secret_data_handling": str(),
	}, "capability", "operation", "ready", "effect_free", "provider_id", "provider_type", "provider_label", "role", "requested_ttl_seconds", "effective_ttl_seconds", "maximum_ttl_seconds", "configuration_revision", "required_permission", "request_fingerprint", "blockers", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "secret_data_handling")
	rotationProvider := str()
	rotationProvider.Description = "connector:<target> is the only executable mode. Static and dynamic-lease providers are unavailable and fail closed with 503 before effects."
	rotationTTL := &Schema{Type: "integer"}
	rotationTTL.Description = "Compatibility input only. Connector requests reject any supplied ttl_seconds with 400. Static and dynamic-lease providers remain unavailable with 503 regardless of this field."
	secretRotationReq := object(map[string]*Schema{
		"provider": rotationProvider, "key": str(), "old_ref": str(),
		"target": str(), "remote_key": str(), "ttl_seconds": rotationTTL,
	}, "provider", "key", "old_ref")
	secretRotation := object(map[string]*Schema{
		"key": str(), "old_ref": str(), "new_ref": str(),
		"completed": {Type: "boolean"}, "queued": {Type: "boolean"}, "rolled_back": {Type: "boolean"},
		"rollback_attempted": {Type: "boolean"}, "rollback_failed": {Type: "boolean"},
		"rollback_error": str(), "failed_phase": str(), "error": str(),
	}, "key", "old_ref", "new_ref", "completed", "queued", "rolled_back", "rollback_attempted", "rollback_failed")
	secretRotationPreview := object(map[string]*Schema{
		"capability": {Type: "string", Enum: []string{"F37"}},
		"ready":      {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"provider": str(), "key": str(), "old_ref": str(), "target": str(), "remote_key": str(),
		"current_version": {Type: "integer"}, "next_version": {Type: "integer"},
		"required_permission": str(), "request_fingerprint": str(),
		"blockers":                 {Type: "array", Items: str()},
		"preview_writes":           {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()},
		"execute_writes":           {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps":           {Type: "array", Items: str()},
		"secret_data_handling":     str(),
	}, "capability", "ready", "effect_free", "provider", "key", "old_ref", "required_permission", "request_fingerprint", "blockers", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "secret_data_handling")
	secretRotationScheduleProvider := str()
	secretRotationScheduleProvider.Description = "connector:<target> only. Static and dynamic-lease schedules fail closed with 503 before persistence because their provider phases do not yet have a durable worker command."
	secretRotationScheduleReq := object(map[string]*Schema{
		"name": str(), "provider": secretRotationScheduleProvider, "key": str(), "old_ref": str(),
		"interval_seconds": {Type: "integer"}, "enabled": {Type: "boolean"},
		"next_run_at": timestamp(),
	}, "name", "provider", "key", "old_ref", "interval_seconds")
	secretRotationRunStatuses := []string{
		"completed", "queued", "failed", "rolled_back", "rollback_failed", "retire_pending", "delivery_failed", "unsupported",
	}
	secretRotationScheduleLastRunStatus := str()
	secretRotationScheduleLastRunStatus.Enum = append([]string{""}, secretRotationRunStatuses...)
	secretRotationScheduleLastRunStatus.Description = "Empty means never run. delivery_failed proves the connector's canonical local successor committed. unsupported marks and disables a historical non-connector schedule without invoking its provider. retire_pending is retained compatibility evidence from pre-durable static histories. Generic failed does not advance old_ref."
	secretRotationSchedule := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "provider": str(),
		"key": str(), "old_ref": str(), "interval_seconds": {Type: "integer"},
		"enabled": {Type: "boolean"}, "next_run_at": timestamp(),
		"last_run_id": uuid(), "last_run_at": timestamp(), "last_run_status": secretRotationScheduleLastRunStatus,
		"last_new_ref": str(), "last_error": str(),
		"created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "name", "provider", "key", "old_ref", "interval_seconds", "enabled", "next_run_at", "last_run_status", "created_at", "updated_at")
	secretRotationScheduleRunStatus := str()
	secretRotationScheduleRunStatus.Enum = secretRotationRunStatuses
	secretRotationScheduleRunStatus.Description = "delivery_failed has explicit committed-successor authority. unsupported proves a historical non-connector row was disabled with zero provider calls. retire_pending is compatibility evidence from older static histories; generic failed carries no successor authority."
	secretRotationScheduleRun := object(map[string]*Schema{
		"schedule_id": uuid(), "run_id": uuid(), "due_at": timestamp(), "status": secretRotationScheduleRunStatus,
		"rotation": ref("SecretRotation"), "error": str(), "ran_at": timestamp(),
		"reconciled": {Type: "boolean", Description: "True when this response was reconstructed from the retained deterministic terminal event without re-running the child command."},
	}, "schedule_id", "run_id", "due_at", "status", "rotation", "ran_at", "reconciled")
	secretRotationDeferredReason := str()
	secretRotationDeferredReason.Enum = []string{"approval_pending", "command_in_flight", "command_claimed", "config_revision_unanchored"}
	secretRotationDeferredReason.Description = "Row-local retry state. The exact due edge and command identity remain unchanged for a later tick. config_revision_unanchored means a pre-evidence schedule was scanned and diagnosed without creating a child command or invoking a provider."
	secretRotationScheduleDeferred := object(map[string]*Schema{
		"schedule_id": uuid(), "reason": secretRotationDeferredReason, "due_at": timestamp(),
		"error": {Type: "string", Description: "Non-secret reason detail for this exact deferred due edge."},
	}, "schedule_id", "reason", "due_at")
	secretRotationDueRan := &Schema{Type: "integer", Description: "Durable run records written in this tick, including terminal row-local failures; maximum 50."}
	secretRotationDueScanned := &Schema{Type: "integer", Description: "Due schedule rows inspected from the durable fair UUID ring in this tick; maximum 500."}
	secretRotationRunLimitReached := &Schema{Type: "boolean", Description: "True when the full 50-run budget was consumed. The captured due ring was not proven exhausted, so another tick with a new Idempotency-Key may be required."}
	secretRotationScanLimitReached := &Schema{Type: "boolean", Description: "True when the full 500-row scan budget was consumed. The captured due ring was not proven exhausted, so another tick with a new Idempotency-Key may be required."}
	secretRotationDueComplete := &Schema{Type: "boolean", Description: "True only when the fixed PostgreSQL due-through UUID ring was proven exhausted without a subsystem/store/event/custody failure. False when either safety budget was consumed or a system failure stopped the tick."}
	secretRotationDuePartial := &Schema{Type: "boolean", Description: "True when at least one run or deferred row was recorded before a subsystem failure stopped this tick."}
	secretRotationDueRun := object(map[string]*Schema{
		"ran": secretRotationDueRan, "scanned": secretRotationDueScanned,
		"runs":              {Type: "array", Items: ref("SecretRotationScheduleRun")},
		"deferred":          {Type: "array", Items: ref("SecretRotationScheduleDeferred")},
		"run_limit_reached": secretRotationRunLimitReached, "scan_limit_reached": secretRotationScanLimitReached,
		"complete": secretRotationDueComplete, "partial": secretRotationDuePartial,
		"failed_schedule_id": {Type: "string", Format: "uuid", Description: "Due schedule at which a subsystem failure stopped the batch; omitted for scan/retention failures."},
		"system_error":       {Type: "string", Description: "Non-secret fail-stop detail. A 503 envelope is cached by the outer Idempotency-Key; retry with the same key is byte-identical and executes no child again. Use a new key to continue after repair."},
	}, "ran", "scanned", "runs", "deferred", "run_limit_reached", "scan_limit_reached", "complete", "partial")
	secretSyncReq := object(map[string]*Schema{
		"name": str(), "target": str(), "remote_key": str(), "preview_fingerprint": str(),
	}, "name", "target")
	secretSyncPreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"name": str(), "secret_version": {Type: "integer"}, "target": str(), "remote_key": str(),
		"required_permission": str(), "request_fingerprint": str(),
		"blockers": {Type: "array", Items: str()}, "preview_reads": {Type: "array", Items: str()},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()},
		"execute_writes": {Type: "array", Items: str()}, "execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()}, "verification_steps": {Type: "array", Items: str()},
		"cli_argv": {Type: "array", Items: str()}, "secret_data_handling": str(),
	}, "capability", "operation", "ready", "effect_free", "name", "secret_version", "target", "remote_key",
		"required_permission", "blockers", "preview_reads", "preview_writes", "preview_external_effects",
		"execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "secret_data_handling")
	secretSync := object(map[string]*Schema{
		"name": str(), "target": str(), "remote_key": str(),
		"enqueued": {Type: "boolean"}, "delivered": {Type: "boolean"},
	}, "name", "target", "remote_key", "enqueued", "delivered")
	secretSyncTarget := object(map[string]*Schema{
		"id": str(), "name": str(), "platform": str(),
		"configured":      {Type: "boolean"},
		"delivery_mode":   str(),
		"auth_mode":       str(),
		"wire_format":     str(),
		"secret_handling": str(),
		"capabilities":    {Type: "array", Items: str()},
	}, "id", "name", "platform", "configured", "delivery_mode", "auth_mode", "wire_format", "secret_handling", "capabilities")
	secretSyncTargetCatalog := object(map[string]*Schema{
		"capability":         str(),
		"served":             {Type: "boolean"},
		"generated_at":       timestamp(),
		"targets":            {Type: "array", Items: ref("SecretSyncTarget")},
		"configured_targets": {Type: "array", Items: str()},
		"outbox_mode":        str(),
		"evidence_refs":      {Type: "array", Items: str()},
		"residuals":          {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "targets", "configured_targets", "outbox_mode", "evidence_refs", "residuals")
	cloudSecretManagerProvider := object(map[string]*Schema{
		"id":                     str(),
		"name":                   str(),
		"platform":               str(),
		"discovery_supported":    {Type: "boolean"},
		"discovery_configured":   {Type: "boolean"},
		"discovery_source_kind":  str(),
		"discovery_source_count": {Type: "integer"},
		"discovery_read_ops":     {Type: "array", Items: str()},
		"sync_supported":         {Type: "boolean"},
		"sync_configured":        {Type: "boolean"},
		"sync_target_id":         str(),
		"sync_write_operation":   str(),
		"secret_handling":        str(),
		"capabilities":           {Type: "array", Items: str()},
		"evidence_refs":          {Type: "array", Items: str()},
	}, "id", "name", "platform", "discovery_supported", "discovery_configured", "discovery_source_count", "discovery_read_ops", "sync_supported", "sync_configured", "secret_handling", "capabilities", "evidence_refs")
	cloudSecretManagerSummary := object(map[string]*Schema{
		"total_providers":        {Type: "integer"},
		"discovery_supported":    {Type: "integer"},
		"discovery_configured":   {Type: "integer"},
		"sync_supported":         {Type: "integer"},
		"sync_configured":        {Type: "integer"},
		"fully_configured":       {Type: "integer"},
		"configured_connections": {Type: "integer"},
	}, "total_providers", "discovery_supported", "discovery_configured", "sync_supported", "sync_configured", "fully_configured", "configured_connections")
	cloudSecretManagerIntegration := object(map[string]*Schema{
		"capability":               str(),
		"served":                   {Type: "boolean"},
		"generated_at":             timestamp(),
		"summary":                  ref("CloudSecretManagerSummary"),
		"providers":                {Type: "array", Items: ref("CloudSecretManagerProvider")},
		"configured_providers":     {Type: "array", Items: str()},
		"configured_sync_targets":  {Type: "array", Items: str()},
		"discovery_mode":           str(),
		"outbox_mode":              str(),
		"secret_handling":          str(),
		"architecture_controls":    {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"residuals":                {Type: "array", Items: str()},
		"recommended_next_actions": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "summary", "providers", "configured_providers", "configured_sync_targets", "discovery_mode", "outbox_mode", "secret_handling", "architecture_controls", "evidence_refs", "residuals", "recommended_next_actions")
	kubernetesSecretOperatorCRD := object(map[string]*Schema{
		"kind":         str(),
		"api_group":    str(),
		"api_version":  str(),
		"plural":       str(),
		"status":       str(),
		"owns":         {Type: "array", Items: str()},
		"evidence_ref": str(),
	}, "kind", "api_group", "api_version", "plural", "status", "owns", "evidence_ref")
	kubernetesSecretOperator := object(map[string]*Schema{
		"capability":               str(),
		"served":                   {Type: "boolean"},
		"generated_at":             timestamp(),
		"crds":                     {Type: "array", Items: ref("KubernetesSecretOperatorCRD")},
		"sync_flow":                {Type: "array", Items: str()},
		"reload_workloads":         {Type: "array", Items: str()},
		"secret_handling":          str(),
		"architecture_controls":    {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"residuals":                {Type: "array", Items: str()},
		"recommended_next_actions": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "crds", "sync_flow", "reload_workloads", "secret_handling", "architecture_controls", "evidence_refs", "residuals", "recommended_next_actions")
	secretWorkloadInjectionCRD := object(map[string]*Schema{
		"kind":         str(),
		"api_group":    str(),
		"api_version":  str(),
		"plural":       str(),
		"status":       str(),
		"owns":         {Type: "array", Items: str()},
		"evidence_ref": str(),
	}, "kind", "api_group", "api_version", "plural", "status", "owns", "evidence_ref")
	secretWorkloadInjectionMode := object(map[string]*Schema{
		"id":              str(),
		"name":            str(),
		"delivered_by":    str(),
		"workload_change": str(),
		"secret_handling": str(),
		"capabilities":    {Type: "array", Items: str()},
	}, "id", "name", "delivered_by", "workload_change", "secret_handling", "capabilities")
	secretWorkloadInjection := object(map[string]*Schema{
		"capability":               str(),
		"served":                   {Type: "boolean"},
		"generated_at":             timestamp(),
		"crd":                      ref("SecretWorkloadInjectionCRD"),
		"modes":                    {Type: "array", Items: ref("SecretWorkloadInjectionMode")},
		"workload_kinds":           {Type: "array", Items: str()},
		"sidecar_command":          {Type: "array", Items: str()},
		"annotations":              {Type: "array", Items: str()},
		"sync_dependency":          str(),
		"secret_handling":          str(),
		"architecture_controls":    {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"residuals":                {Type: "array", Items: str()},
		"recommended_next_actions": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "crd", "modes", "workload_kinds", "sidecar_command", "annotations", "sync_dependency", "secret_handling", "architecture_controls", "evidence_refs", "residuals", "recommended_next_actions")
	unvaultedSecretSummary := object(map[string]*Schema{
		"repository_sources":        {Type: "integer"},
		"third_party_sources":       {Type: "integer"},
		"cloud_secret_sources":      {Type: "integer"},
		"vault_providers_supported": {Type: "integer"},
		"vault_providers_visible":   {Type: "integer"},
		"sync_targets_configured":   {Type: "integer"},
		"leaked_secret_findings":    {Type: "integer"},
	}, "repository_sources", "third_party_sources", "cloud_secret_sources", "vault_providers_supported", "vault_providers_visible", "sync_targets_configured", "leaked_secret_findings")
	unvaultedSecretDetectionSource := object(map[string]*Schema{
		"id":               str(),
		"name":             str(),
		"source_kind":      str(),
		"configured_count": {Type: "integer"},
		"detection_mode":   str(),
		"secret_handling":  str(),
		"findings_kind":    str(),
		"capabilities":     {Type: "array", Items: str()},
		"evidence_refs":    {Type: "array", Items: str()},
	}, "id", "name", "source_kind", "configured_count", "detection_mode", "secret_handling", "findings_kind", "capabilities", "evidence_refs")
	unvaultedSecretVaultProvider := object(map[string]*Schema{
		"id":                     str(),
		"name":                   str(),
		"discovery_configured":   {Type: "boolean"},
		"discovery_source_count": {Type: "integer"},
		"sync_supported":         {Type: "boolean"},
		"sync_configured":        {Type: "boolean"},
		"augmentation_mode":      str(),
		"capabilities":           {Type: "array", Items: str()},
		"evidence_refs":          {Type: "array", Items: str()},
	}, "id", "name", "discovery_configured", "discovery_source_count", "sync_supported", "sync_configured", "augmentation_mode", "capabilities", "evidence_refs")
	unvaultedSecretPosture := object(map[string]*Schema{
		"capability":               str(),
		"served":                   {Type: "boolean"},
		"generated_at":             timestamp(),
		"summary":                  ref("UnvaultedSecretSummary"),
		"detection_sources":        {Type: "array", Items: ref("UnvaultedSecretDetectionSource")},
		"vault_providers":          {Type: "array", Items: ref("UnvaultedSecretVaultProvider")},
		"configured_vaults":        {Type: "array", Items: str()},
		"configured_sync_targets":  {Type: "array", Items: str()},
		"workflow":                 {Type: "array", Items: str()},
		"secret_handling":          str(),
		"architecture_controls":    {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"residuals":                {Type: "array", Items: str()},
		"recommended_next_actions": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "summary", "detection_sources", "vault_providers", "configured_vaults", "configured_sync_targets", "workflow", "secret_handling", "architecture_controls", "evidence_refs", "residuals", "recommended_next_actions")
	kubernetesPostureSummary := object(map[string]*Schema{
		"controllers":          {Type: "integer"},
		"complete_controllers": {Type: "integer"},
		"stale_controllers":    {Type: "integer"},
		"observed":             {Type: "integer"},
		"ready":                {Type: "integer"},
		"pending":              {Type: "integer"},
		"failed":               {Type: "integer"},
	}, "controllers", "complete_controllers", "stale_controllers", "observed", "ready", "pending", "failed")
	kubernetesPostureController := object(map[string]*Schema{
		"controller_id":      str(),
		"cluster_id":         str(),
		"report_id":          str(),
		"reconcile_complete": {Type: "boolean"},
		"failure_code":       str(),
		"last_sync":          timestamp(),
		"stale":              {Type: "boolean"},
		"observed":           {Type: "integer"},
		"ready":              {Type: "integer"},
		"pending":            {Type: "integer"},
		"failed":             {Type: "integer"},
	}, "controller_id", "cluster_id", "report_id", "reconcile_complete", "last_sync", "stale", "observed", "ready", "pending", "failed")
	kubernetesPostureObject := object(map[string]*Schema{
		"controller_id":    str(),
		"cluster_id":       str(),
		"namespace":        str(),
		"name":             str(),
		"uid":              str(),
		"resource_version": str(),
		"state":            {Type: "string", Enum: []string{"ready", "pending", "failed"}},
		"reason":           str(),
		"public_hash":      str(),
	}, "controller_id", "cluster_id", "name", "uid", "resource_version", "state", "reason")
	kubernetesCSRSupportRule := object(map[string]*Schema{
		"api_group": str(), "resource": str(), "verbs": {Type: "array", Items: str()},
	}, "api_group", "resource", "verbs")
	// Preserve the original descriptor fields and required set so older clients
	// remain source-compatible. The four posture fields are additive and optional
	// in the contract; a current server always emits them from controller-reported
	// state, and never derives served truth from these legacy descriptors.
	kubernetesCSRSupport := object(map[string]*Schema{
		"capability":               str(),
		"served":                   {Type: "boolean"},
		"generated_at":             timestamp(),
		"api_group":                str(),
		"api_version":              str(),
		"resource":                 str(),
		"signer_names":             {Type: "array", Items: str()},
		"controller_flow":          {Type: "array", Items: str()},
		"rbac_rules":               {Type: "array", Items: ref("KubernetesCSRSupportRule")},
		"status_fields":            {Type: "array", Items: str()},
		"architecture_controls":    {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"residuals":                {Type: "array", Items: str()},
		"recommended_next_actions": {Type: "array", Items: str()},
		"last_sync":                timestamp(),
		"summary":                  ref("KubernetesPostureSummary"),
		"controllers":              {Type: "array", Items: ref("KubernetesPostureController")},
		"objects":                  {Type: "array", Items: ref("KubernetesPostureObject")},
	}, "capability", "served", "generated_at", "api_group", "api_version", "resource", "signer_names", "controller_flow", "rbac_rules", "status_fields", "architecture_controls", "evidence_refs", "residuals", "recommended_next_actions")
	kubernetesTrustBundleDistribution := object(map[string]*Schema{
		"capability":               str(),
		"served":                   {Type: "boolean"},
		"generated_at":             timestamp(),
		"api_group":                str(),
		"api_version":              str(),
		"resource":                 str(),
		"distribution_targets":     {Type: "array", Items: str()},
		"controller_flow":          {Type: "array", Items: str()},
		"rbac_rules":               {Type: "array", Items: ref("KubernetesCSRSupportRule")},
		"status_fields":            {Type: "array", Items: str()},
		"architecture_controls":    {Type: "array", Items: str()},
		"evidence_refs":            {Type: "array", Items: str()},
		"residuals":                {Type: "array", Items: str()},
		"recommended_next_actions": {Type: "array", Items: str()},
		"last_sync":                timestamp(),
		"summary":                  ref("KubernetesPostureSummary"),
		"controllers":              {Type: "array", Items: ref("KubernetesPostureController")},
		"objects":                  {Type: "array", Items: ref("KubernetesPostureObject")},
	}, "capability", "served", "generated_at", "api_group", "api_version", "resource", "distribution_targets", "controller_flow", "rbac_rules", "status_fields", "architecture_controls", "evidence_refs", "residuals", "recommended_next_actions")
	secretScanReq := object(map[string]*Schema{
		"path": str(), "mode": str(), "custom_rules_path": str(),
		"preview_fingerprint": {Type: "string", Description: "Optional server-keyed fingerprint returned by SecretScanPreview. When supplied, execution fails closed if tenant, caller, target, mode, custom rules, or scanner capabilities changed."},
	}, "path")
	secretScanPreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"target_path": str(), "mode": str(), "custom_rules": {Type: "boolean"}, "custom_rules_path": str(), "custom_rules_sha256": str(),
		"scanner": str(), "rules_active": {Type: "integer"}, "capabilities": {Type: "array", Items: str()},
		"required_permission": str(), "request_fingerprint": str(), "blockers": {Type: "array", Items: str()},
		"prerequisites": {Type: "array", Items: str()}, "preview_writes": {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()}, "execute_writes": {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()}, "recovery_steps": {Type: "array", Items: str()},
		"verification_steps": {Type: "array", Items: str()}, "cli_argv": {Type: "array", Items: str()},
		"secret_data_handling": str(),
	}, "capability", "operation", "ready", "effect_free", "target_path", "mode", "custom_rules", "scanner", "rules_active", "capabilities", "required_permission", "request_fingerprint", "blockers", "prerequisites", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "secret_data_handling")
	secretScanFinding := object(map[string]*Schema{
		"rule_id": str(), "file": str(), "line": {Type: "integer"}, "credential_ref": str(),
	}, "rule_id", "file", "line", "credential_ref")
	secretScan := object(map[string]*Schema{
		"run_id": uuid(), "scanner": str(), "engine_version": str(),
		"mode": str(), "custom_rules": {Type: "boolean"},
		"capabilities": {Type: "array", Items: str()},
		"rules_active": {Type: "integer"}, "findings_count": {Type: "integer"},
		"findings": {Type: "array", Items: ref("SecretScanFinding")},
	}, "run_id", "scanner", "engine_version", "mode", "custom_rules", "capabilities", "rules_active", "findings_count", "findings")
	secretRepoProvider := object(map[string]*Schema{
		"id": str(), "name": str(),
		"realtime_triggers": {Type: "array", Items: str()},
		"auth_mode":         str(),
		"ingest_mode":       str(),
		"ref_types":         {Type: "array", Items: str()},
		"secret_handling":   str(),
		"outbox_mode":       str(),
	}, "id", "name", "realtime_triggers", "auth_mode", "ingest_mode", "ref_types", "secret_handling", "outbox_mode")
	secretRepoGate := object(map[string]*Schema{
		"id": str(), "command": str(), "artifact": str(), "required": {Type: "boolean"},
	}, "id", "command", "artifact", "required")
	secretRepoPosture := object(map[string]*Schema{
		"capability": str(), "served": {Type: "boolean"}, "generated_at": str(),
		"providers":             {Type: "array", Items: ref("SecretRepositoryScanProvider")},
		"webhook_paths":         {Type: "array", Items: str()},
		"queue_model":           str(),
		"scanner":               str(),
		"minimum_rules_active":  {Type: "integer"},
		"redaction_model":       str(),
		"event_flow":            {Type: "array", Items: str()},
		"release_gates":         {Type: "array", Items: ref("SecretRepositoryScanGate")},
		"operator_actions":      {Type: "array", Items: str()},
		"residuals":             {Type: "array", Items: str()},
		"evidence_refs":         {Type: "array", Items: str()},
		"architecture_controls": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "providers", "webhook_paths", "queue_model", "scanner", "minimum_rules_active", "redaction_model", "event_flow", "release_gates", "operator_actions", "residuals", "evidence_refs", "architecture_controls")
	secretRepoWebhookReq := object(map[string]*Schema{
		"repository": str(), "clone_url": str(), "checkout_path": str(), "ref": str(),
		"commit_sha": str(), "event": str(), "credential_ref": str(),
	}, "repository")
	secretRepoWebhookReceipt := object(map[string]*Schema{
		"capability": str(), "provider": str(), "repository": str(), "source_id": uuid(),
		"run_id": uuid(), "queued": {Type: "boolean"}, "status": str(),
		"outbox_destination": str(), "scanner": str(), "discovery_run_path": str(),
	}, "capability", "provider", "repository", "source_id", "run_id", "queued", "status", "outbox_destination", "scanner", "discovery_run_path")
	thirdPartySecretScanProvider := object(map[string]*Schema{
		"id": str(), "name": str(),
		"artifact_kinds":  {Type: "array", Items: str()},
		"ingest_mode":     str(),
		"secret_handling": str(),
		"outbox_mode":     str(),
	}, "id", "name", "artifact_kinds", "ingest_mode", "secret_handling", "outbox_mode")
	thirdPartySecretScanPosture := object(map[string]*Schema{
		"capability": str(), "served": {Type: "boolean"}, "generated_at": str(),
		"providers":             {Type: "array", Items: ref("ThirdPartySecretScanProvider")},
		"ingest_paths":          {Type: "array", Items: str()},
		"queue_model":           str(),
		"scanner":               str(),
		"minimum_rules_active":  {Type: "integer"},
		"redaction_model":       str(),
		"event_flow":            {Type: "array", Items: str()},
		"release_gates":         {Type: "array", Items: ref("SecretRepositoryScanGate")},
		"operator_actions":      {Type: "array", Items: str()},
		"residuals":             {Type: "array", Items: str()},
		"evidence_refs":         {Type: "array", Items: str()},
		"architecture_controls": {Type: "array", Items: str()},
	}, "capability", "served", "generated_at", "providers", "ingest_paths", "queue_model", "scanner", "minimum_rules_active", "redaction_model", "event_flow", "release_gates", "operator_actions", "residuals", "evidence_refs", "architecture_controls")
	thirdPartySecretScanIngestReq := object(map[string]*Schema{
		"source": str(), "artifact_path": str(), "artifact_kind": str(), "event": str(), "credential_ref": str(),
	}, "source", "artifact_path")
	thirdPartySecretScanReceipt := object(map[string]*Schema{
		"capability": str(), "provider": str(), "source": str(), "source_id": uuid(),
		"run_id": uuid(), "queued": {Type: "boolean"}, "status": str(),
		"outbox_destination": str(), "scanner": str(), "discovery_run_path": str(),
	}, "capability", "provider", "source", "source_id", "run_id", "queued", "status", "outbox_destination", "scanner", "discovery_run_path")
	dynamicLeaseRenewReq := object(map[string]*Schema{
		"extend_seconds": {Type: "integer"},
	}, "extend_seconds")
	dynamicLease := object(map[string]*Schema{
		"id": str(), "provider": str(), "role": str(), "state": str(),
		"credential": str(), "issued_at": timestamp(), "expires_at": timestamp(),
		"hard_expires_at":   {Type: "string", Format: "date-time", Description: "Original lease renewal ceiling. Not proof of native credential expiry."},
		"revocation_status": {Type: "string", Enum: []string{"none", "pending", "completed", "failed"}, Description: "Provider revocation progress. Revoked lease state alone acknowledges queuing, not provider removal."},
		"revoked_at":        timestamp(), "revocation_completed_at": timestamp(),
	}, "id", "provider", "role", "state", "issued_at", "expires_at")
	transitKeyReq := object(map[string]*Schema{
		"name": str(), "kind": str(),
	}, "name", "kind")
	transitRotateReq := object(map[string]*Schema{
		"name": str(),
	}, "name")
	transitKey := object(map[string]*Schema{
		"name": str(), "kind": str(), "version": {Type: "integer"},
	}, "name", "kind", "version")
	transitKeyList := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("TransitKey")},
	}, "items")
	transitKeyVersion := object(map[string]*Schema{
		"version": {Type: "integer"}, "current": {Type: "boolean"},
	}, "version", "current")
	transitKeyVersionList := object(map[string]*Schema{
		"name": str(), "kind": str(), "versions": {Type: "array", Items: ref("TransitKeyVersion")},
	}, "name", "kind", "versions")
	transitServicePosture := object(map[string]*Schema{
		"served": {Type: "boolean"}, "persistence_configured": {Type: "boolean"},
		"restore_state": str(), "recovery_ready": {Type: "boolean"}, "detail": str(), "recovery": str(),
	}, "served", "persistence_configured", "restore_state", "recovery_ready", "detail")
	kmipPosture := object(map[string]*Schema{
		"state": str(), "configured": {Type: "boolean"}, "served": {Type: "boolean"},
		"listening": {Type: "boolean"}, "tenant_bound": {Type: "boolean"}, "address": str(),
		"transport": str(), "profile": str(), "objects": {Type: "array", Items: str()},
		"operations": {Type: "array", Items: str()}, "detail": str(), "recovery": str(),
	}, "state", "configured", "served", "listening", "tenant_bound", "transport", "profile", "objects", "operations", "detail")
	transitPosture := object(map[string]*Schema{
		"checked_at": timestamp(), "effect_free": {Type: "boolean"},
		"transit": ref("TransitServicePosture"), "kmip": ref("KMIPPosture"),
		"recovery_steps": {Type: "array", Items: str()}, "proof": {Type: "array", Items: str()},
	}, "checked_at", "effect_free", "transit", "kmip", "recovery_steps", "proof")
	transitEncryptReq := object(map[string]*Schema{
		"key": str(), "plaintext": {Type: "string", Format: "byte"}, "aad": {Type: "string", Format: "byte"},
	}, "key", "plaintext")
	transitCiphertextReq := object(map[string]*Schema{
		"key": str(), "ciphertext": str(), "aad": {Type: "string", Format: "byte"},
	}, "key", "ciphertext")
	transitCiphertext := object(map[string]*Schema{
		"ciphertext": str(), "version": {Type: "integer"},
	}, "ciphertext", "version")
	transitPlaintext := object(map[string]*Schema{
		"plaintext": {Type: "string", Format: "byte"},
	}, "plaintext")
	transitHMACReq := object(map[string]*Schema{
		"key": str(), "data": {Type: "string", Format: "byte"},
	}, "key", "data")
	transitHMAC := object(map[string]*Schema{
		"hmac": {Type: "string", Format: "byte"},
	}, "hmac")
	transitSignReq := object(map[string]*Schema{
		"key": str(), "message": {Type: "string", Format: "byte"},
	}, "key", "message")
	transitSignature := object(map[string]*Schema{
		"signature": {Type: "string", Format: "byte"}, "public_der": {Type: "string", Format: "byte"},
	}, "signature", "public_der")
	transitVerifyReq := object(map[string]*Schema{
		"message": {Type: "string", Format: "byte"}, "signature": {Type: "string", Format: "byte"}, "public_der": {Type: "string", Format: "byte"},
	}, "message", "signature", "public_der")
	transitVerify := object(map[string]*Schema{
		"valid": {Type: "boolean"},
	}, "valid")
	codeSigningReq := object(map[string]*Schema{
		"key_id": str(), "artifact_type": str(), "digest": {Type: "string", Format: "byte"}, "preview_fingerprint": str(),
	}, "key_id", "artifact_type", "digest")
	codeSigningKeylessReq := object(map[string]*Schema{
		"artifact_type": str(), "digest": {Type: "string", Format: "byte"},
		"identity_method": str(), "identity_payload": {Type: "string", Format: "byte"},
		"fulcio_san": str(), "fulcio_issuer": str(), "preview_fingerprint": str(),
	}, "artifact_type", "digest", "identity_method", "identity_payload")
	codeSigningPreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "mode": {Type: "string", Enum: []string{"key", "keyless"}},
		"ready": {Type: "boolean"}, "effect_free": {Type: "boolean"}, "artifact_type": str(), "digest_sha256": str(),
		"key_id": str(), "identity_method": str(), "required_permission": str(),
		"request_fingerprint": str(), "configuration_fingerprint": str(), "signing_algorithm": str(),
		"transparency_destination": str(), "approval_required": {Type: "boolean"},
		"blockers": {Type: "array", Items: str()}, "preview_reads": {Type: "array", Items: str()},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()},
		"execute_writes": {Type: "array", Items: str()}, "execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()}, "verification_steps": {Type: "array", Items: str()},
		"cli_argv": {Type: "array", Items: str()}, "secret_data_handling": str(),
	}, "capability", "operation", "mode", "ready", "effect_free", "artifact_type", "digest_sha256",
		"required_permission", "request_fingerprint", "configuration_fingerprint", "approval_required", "blockers",
		"preview_reads", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects",
		"recovery_steps", "verification_steps", "cli_argv", "secret_data_handling")
	codeSigningSignature := object(map[string]*Schema{
		"algorithm": str(), "key_id": str(), "artifact_type": str(),
		"signature": {Type: "string", Format: "byte"}, "public_key_der": {Type: "string", Format: "byte"},
		"fulcio_san": str(), "fulcio_issuer": str(), "transparency_destination": str(),
	}, "algorithm", "artifact_type", "signature", "public_key_der")
	// Managed-key (BYOK/HSM) lifecycle schemas (CRYPTO-005). public_der is the PKIX
	// public key (base64 in JSON); the private material is never represented here.
	managedKeyGenerateReq := object(map[string]*Schema{
		"algorithm": {Type: "string", Enum: []string{"RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"}},
	}, "algorithm")
	managedKeyProviderIDs := []string{"aws", "azure-key-vault", "gcp-kms", "pkcs11", "tpm2", "yubihsm2"}
	managedKeyCustodyRequirement := object(map[string]*Schema{
		"key": str(), "label": str(), "kind": {Type: "string", Enum: []string{"value", "secret_file"}},
		"required": {Type: "boolean"}, "environment_variable": str(), "description": str(),
	}, "key", "label", "kind", "required", "environment_variable", "description")
	managedKeyCustodyProvider := object(map[string]*Schema{
		"id": {Type: "string", Enum: managedKeyProviderIDs}, "label": str(), "custody": str(),
		"requirements": {Type: "array", Items: &Schema{Ref: "#/components/schemas/ManagedKeyCustodyRequirement"}},
	}, "id", "label", "custody", "requirements")
	managedKeyCustodyPlan := object(map[string]*Schema{
		"enabled": {Type: "boolean"}, "lifecycle_attached": {Type: "boolean"}, "ready": {Type: "boolean"},
		"configured_provider": {Type: "string", Enum: append([]string{""}, managedKeyProviderIDs...)},
		"configuration_mode":  {Type: "string", Enum: []string{"startup_static"}},
		"secret_delivery":     {Type: "string", Enum: []string{"file_reference_only"}},
		"restart_required":    {Type: "boolean"}, "security_boundary": str(),
		"providers": {Type: "array", Items: &Schema{Ref: "#/components/schemas/ManagedKeyCustodyProvider"}},
		"blockers":  {Type: "array", Items: str()},
	}, "enabled", "lifecycle_attached", "ready", "configured_provider", "configuration_mode", "secret_delivery", "restart_required", "security_boundary", "providers", "blockers")
	managedKeyGenerationPreviewReq := object(map[string]*Schema{
		"provider":  {Type: "string", Enum: managedKeyProviderIDs},
		"algorithm": {Type: "string", Enum: []string{"RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"}},
	}, "provider", "algorithm")
	managedKeyGenerationPreview := object(map[string]*Schema{
		"ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"provider": {Type: "string", Enum: managedKeyProviderIDs}, "provider_label": str(), "algorithm": str(),
		"configuration_mode": {Type: "string", Enum: []string{"startup_static"}}, "restart_required": {Type: "boolean"},
		"extractable": {Type: "boolean"}, "private_key_location": str(), "required_permission": str(), "approval_required": {Type: "boolean"},
		"requirements":   {Type: "array", Items: &Schema{Ref: "#/components/schemas/ManagedKeyCustodyRequirement"}},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()},
		"execution_writes": {Type: "array", Items: str()}, "execution_external_effects": {Type: "array", Items: str()},
		"proof": {Type: "array", Items: str()}, "blockers": {Type: "array", Items: str()},
	}, "ready", "effect_free", "provider", "provider_label", "algorithm", "configuration_mode", "restart_required", "extractable", "private_key_location", "required_permission", "approval_required", "requirements", "preview_writes", "preview_external_effects", "execution_writes", "execution_external_effects", "proof", "blockers")
	managedKeyActionReq := object(map[string]*Schema{
		"key_id": str(),
	}, "key_id")
	managedKeyApprovalReq := object(map[string]*Schema{
		"key_id": str(), "action": {Type: "string", Enum: managedKeyApprovalActions},
		"request_id": uuid(), "intent_digest": str(),
	}, "key_id", "action", "request_id", "intent_digest")
	managedKeyApproval := object(map[string]*Schema{
		"resource": str(), "action": {Type: "string", Enum: managedKeyCanonicalApprovalActions},
		"approver": str(), "approvals": {Type: "integer"},
	}, "resource", "action", "approver", "approvals")
	managedKey := object(map[string]*Schema{
		"key_id": str(), "algorithm": str(), "version": {Type: "integer"}, "state": str(),
		"public_der":  {Type: "string", Format: "byte"},
		"extractable": {Type: "boolean"},
	}, "key_id", "algorithm", "version", "state")
	secretValue := object(map[string]*Schema{
		"name": str(), "value": str(), "version": {Type: "integer"},
	}, "name", "value")
	shareReq := object(map[string]*Schema{
		"value": str(), "ttl_seconds": {Type: "integer"},
		"preview_fingerprint": {Type: "string", Description: "Optional server-keyed fingerprint returned by SharePreview. When supplied, creation fails closed if the reviewed lifetime changed."},
	}, "value")
	sharePreviewReq := object(map[string]*Schema{
		"ttl_seconds": {Type: "integer", Description: "Requested lifetime in seconds. Zero selects the 24-hour default; explicit values must be between 60 seconds and 7 days."},
	})
	sharePreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"requested_ttl_seconds": {Type: "integer"}, "effective_ttl_seconds": {Type: "integer"},
		"required_permission": str(), "request_fingerprint": str(), "sensitive_change_approval_configured": {Type: "boolean"},
		"blockers": {Type: "array", Items: str()}, "preview_writes": {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()}, "execute_writes": {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()}, "recovery_steps": {Type: "array", Items: str()},
		"verification_steps": {Type: "array", Items: str()}, "cli_argv": {Type: "array", Items: str()},
		"secret_data_handling": str(),
	}, "capability", "operation", "ready", "effect_free", "requested_ttl_seconds", "effective_ttl_seconds",
		"required_permission", "request_fingerprint", "sensitive_change_approval_configured", "blockers", "preview_writes",
		"preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "secret_data_handling")
	shareToken := object(map[string]*Schema{
		"token": str(), "expires_at": timestamp(),
	}, "token")
	shareRedeemReq := object(map[string]*Schema{
		"token": str(),
	}, "token")
	shareValue := object(map[string]*Schema{
		"value": str(),
	}, "value")
	secretRecoverReq := object(map[string]*Schema{
		"at": timestamp(),
	}, "at")
	pkiSecretReq := object(map[string]*Schema{
		"common_name": {
			Type:        "string",
			Description: "Deprecated server-side-keygen mode: trstctl generates and returns the subject key, and records issuance.server_side_keygen before doing so.",
		},
		"csr_pem": {
			Type:        "string",
			Description: "Recommended requester-key mode: one self-signed PKCS#10 PEM request. trstctl signs it and never receives or returns the matching private key.",
		},
		"ttl_seconds": {Type: "integer"},
		"preview_fingerprint": {
			Type:        "string",
			Description: "Optional server-keyed fingerprint returned by preview. When supplied, execution fails closed if the reviewed tenant, principal, CA, custody input, profile, or TTL changed.",
		},
	})
	pkiSecretReq.OneOf = []*Schema{{Required: []string{"common_name"}}, {Required: []string{"csr_pem"}}}
	pkiSecretPrerequisite := object(map[string]*Schema{
		"id": str(), "ready": {Type: "boolean"}, "detail": str(), "remediation": str(),
	}, "id", "ready", "detail")
	pkiSecretPreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"custody_mode": str(), "common_name": str(), "dns_names": {Type: "array", Items: str()}, "requested_ttl_seconds": {Type: "integer"},
		"effective_ttl_seconds": {Type: "integer"}, "profile": str(), "ca_certificate_sha256": str(),
		"csr_sha256": str(), "subject_key_algorithm": str(), "subject_key_bits": {Type: "integer"},
		"required_permission": str(), "request_fingerprint": str(), "vault_path": str(),
		"prerequisites": {Type: "array", Items: &Schema{Ref: "#/components/schemas/PKISecretPrerequisite"}},
		"blockers":      {Type: "array", Items: str()}, "preview_writes": {Type: "array", Items: str()},
		"preview_external_effects": {Type: "array", Items: str()}, "execute_writes": {Type: "array", Items: str()},
		"execute_external_effects": {Type: "array", Items: str()}, "recovery_steps": {Type: "array", Items: str()},
		"verification_steps": {Type: "array", Items: str()}, "cli_argv": {Type: "array", Items: str()},
		"secret_data_handling": str(),
	}, "capability", "operation", "ready", "effect_free", "custody_mode", "common_name", "dns_names", "requested_ttl_seconds",
		"effective_ttl_seconds", "profile", "subject_key_algorithm", "subject_key_bits", "required_permission",
		"request_fingerprint", "vault_path", "prerequisites", "blockers", "preview_writes", "preview_external_effects",
		"execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "secret_data_handling")
	pkiSecret := object(map[string]*Schema{
		"serial": str(), "common_name": str(), "certificate": str(), "private_key": str(),
	}, "serial", "common_name", "certificate")
	machineLoginReq := object(map[string]*Schema{
		"method": str(), "credential": str(),
		"preview_fingerprint": {Type: "string", Description: "Optional tenant- and method-bound fingerprint from the authenticated preview route. When supplied, login fails closed if method configuration, enabled state, or session lifetime changed."},
	}, "credential")
	machineLoginPreviewReq := object(map[string]*Schema{
		"method": {Type: "string", Description: "Exact configured machine-auth method name. Empty selects the builtin token method for compatibility."},
	})
	machineLoginPrerequisite := object(map[string]*Schema{
		"id": str(), "ready": {Type: "boolean"}, "detail": str(), "remediation": str(),
	}, "id", "ready", "detail")
	machineLoginPreview := object(map[string]*Schema{
		"capability": str(), "operation": str(), "ready": {Type: "boolean"}, "effect_free": {Type: "boolean"},
		"method": {Ref: "#/components/schemas/MachineAuthMethod"}, "tenant_binding": str(), "credential_format": str(),
		"session_ttl_seconds": {Type: "integer"}, "required_permission": str(), "request_fingerprint": str(),
		"prerequisites": {Type: "array", Items: &Schema{Ref: "#/components/schemas/MachineLoginPrerequisite"}},
		"blockers":      {Type: "array", Items: str()}, "preview_reads": {Type: "array", Items: str()},
		"preview_writes": {Type: "array", Items: str()}, "preview_external_effects": {Type: "array", Items: str()},
		"execute_writes": {Type: "array", Items: str()}, "execute_external_effects": {Type: "array", Items: str()},
		"recovery_steps": {Type: "array", Items: str()}, "verification_steps": {Type: "array", Items: str()},
		"cli_argv": {Type: "array", Items: str()}, "secret_data_handling": str(),
	}, "capability", "operation", "ready", "effect_free", "method", "tenant_binding", "credential_format",
		"session_ttl_seconds", "required_permission", "request_fingerprint", "prerequisites", "blockers", "preview_reads",
		"preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps",
		"verification_steps", "cli_argv", "secret_data_handling")
	machineLoginResp := object(map[string]*Schema{
		"session_id": str(),
		"principal":  str(),
		"method":     str(),
		"scopes":     {Type: "array", Items: str()},
		"expires_at": timestamp(),
		"token":      {Type: "string", Description: "One-time opaque bearer for this scoped machine session. The server stores only its hash; copy it before dismissing the response."},
	}, "session_id", "principal", "method", "scopes", "expires_at", "token")

	// Served AI / RCA / NL-query / MCP surface (SURFACE-003). Every request is
	// allow-listed and typed (no raw SQL/Cypher); every answer is grounded in cited
	// REAL records (citations reference actual rows/events), and no key material
	// appears in any response (AN-8). The surfaces a query may name are the typed
	// query-layer surfaces.
	// surfaces is a plain string array (the allow-listed values — owners, certificates,
	// graph, cbom, log — are validated server-side and fail closed on an unknown name);
	// kept un-enumerated so the generated FE type is a clean string[] rather than a
	// union-array.
	aiQueryReq := object(map[string]*Schema{
		"surfaces": {Type: "array", Items: str()},
		"subject":  str(),
		"question": str(),
		"limit":    {Type: "integer"},
	}, "surfaces")
	rcaReq := object(map[string]*Schema{
		"subject": str(), "question": str(),
	}, "question")
	aiAnswer := object(map[string]*Schema{
		"text":       str(),
		"citations":  {Type: "array", Items: str()},
		"sufficient": {Type: "boolean"},
		"grounded":   {Type: "boolean"},
	}, "text", "sufficient")
	aiStatus := object(map[string]*Schema{
		"enabled":               {Type: "boolean"},
		"model_configured":      {Type: "boolean"},
		"model_mode":            str(),
		"model_name":            str(),
		"runtime":               str(),
		"provider":              str(),
		"endpoint_host":         str(),
		"egress":                str(),
		"pii_egress":            str(),
		"redaction":             str(),
		"residual_refusal_gate": {Type: "boolean"},
		"mcp_identity":          str(),
		"mcp_write_tools":       {Type: "boolean"},
		"rate_max":              {Type: "integer"},
		"rate_window_seconds":   {Type: "integer"},
	}, "enabled", "model_configured", "model_mode", "egress", "pii_egress", "redaction", "residual_refusal_gate")
	mcpToolList := object(map[string]*Schema{
		"identity":  str(),
		"read_only": {Type: "boolean"},
		"tools":     {Type: "array", Items: str()},
	}, "read_only", "tools")
	mcpToolCall := object(map[string]*Schema{
		"subject":         str(),
		"authority_id":    str(),
		"csr_pem":         str(),
		"ttl_seconds":     {Type: "integer"},
		"reason":          str(),
		"previous_serial": str(),
	})
	mcpToolResult := object(map[string]*Schema{
		"tool":            str(),
		"citations":       {Type: "array", Items: str()},
		"text":            str(),
		"certificate_pem": str(),
		"serial":          str(),
		"not_after":       timestamp(),
	}, "tool", "text")

	return map[string]*Schema{
		"Problem":                                  problemSchema,
		"CapabilityLicensePosture":                 capabilityLicensePosture,
		"CapabilityViewStage":                      capabilityViewStage,
		"CapabilityUnavailableAction":              capabilityUnavailableAction,
		"CapabilityRuntimeOperation":               capabilityRuntimeOperation,
		"CapabilityViewActions":                    capabilityViewActions,
		"CapabilityViewItem":                       capabilityViewItem,
		"CapabilityView":                           capabilityView,
		"EnterpriseSupportStatus":                  enterpriseSupportStatus,
		"EnterpriseSupportTier":                    enterpriseSupportTier,
		"EnterpriseSupportSLATarget":               enterpriseSupportSLATarget,
		"EnterpriseProfessionalService":            enterpriseProfessionalService,
		"ManagedOfferingStatus":                    managedOfferingStatus,
		"PlatformDistributionStatus":               platformDistributionStatus,
		"PlatformRunMode":                          platformRunMode,
		"PlatformHostArchive":                      platformHostArchive,
		"PlatformAirGap":                           platformAirGap,
		"ScaleOrchestrationPlan":                   scaleOrchestrationPlan,
		"ScaleBand":                                scaleBand,
		"ScaleExecutionLane":                       scaleExecutionLane,
		"ScaleShardPlan":                           scaleShardPlan,
		"ScaleBackpressureRule":                    scaleBackpressureRule,
		"ScaleReleaseGate":                         scaleReleaseGate,
		"ScaleUnitEconomics":                       scaleUnitEconomics,
		"ScaleTenantIsolation":                     scaleTenantIsolation,
		"ScaleDatastorePosture":                    scaleDatastorePosture,
		"ScaleSignerPosture":                       scaleSignerPosture,
		"ScaleProjectionPosture":                   scaleProjectionPosture,
		"ScaleHotPathSLO":                          scaleHotPathSLO,
		"ScaleCapacityTier":                        scaleCapacityTier,
		"ActiveActiveIssuancePlan":                 activeActiveIssuancePlan,
		"IssuanceRegion":                           issuanceRegion,
		"TenantWriteFence":                         tenantWriteFence,
		"RegionalIssuanceLane":                     regionalIssuanceLane,
		"RegionalFailoverStep":                     regionalFailoverStep,
		"ManagedTenantProvisionRequest":            managedTenantReq,
		"ManagedTenant":                            managedTenant,
		"NHIReviewItemRequest":                     nhiReviewItemReq,
		"NHIReviewCampaignStartRequest":            nhiReviewCampaignStartReq,
		"NHIReviewDecisionRequest":                 nhiReviewDecisionReq,
		"NHIReviewItem":                            nhiReviewItem,
		"NHIReviewCampaign":                        nhiReviewCampaign,
		"NHIReviewCampaignList":                    list("NHIReviewCampaign"),
		"PQCMigrationCampaignStartRequest":         pqcCampaignStartReq,
		"PQCMigrationCampaignUpdateRequest":        pqcCampaignUpdateReq,
		"PQCMigrationCampaignReadinessRequest":     pqcCampaignReadinessReq,
		"PQCMigrationFindingDispositionRequest":    campaignFindingDispositionReq,
		"PQCMigrationCampaignCloseRequest":         pqcCampaignCloseReq,
		"PQCMigrationCampaignFinding":              pqcCampaignFinding,
		"PQCMigrationCampaignClosure":              pqcCampaignClosure,
		"PQCMigrationCampaign":                     pqcCampaign,
		"PQCMigrationCampaignList":                 list("PQCMigrationCampaign"),
		"AccessChangeRequestCreateRequest":         accessChangeRequestCreateReq,
		"AccessChangeDecisionRequest":              accessChangeDecisionReq,
		"AccessChangeDecision":                     accessChangeDecision,
		"AccessChangeRequest":                      accessChangeRequest,
		"AccessChangeRequestList":                  list("AccessChangeRequest"),
		"AgentDiscoveryCapability":                 agentDiscoveryCapability,
		"Agent":                                    agent,
		"AgentPresence":                            agentPresence,
		"AgentWorkloadAPIStatus":                   agentWorkloadAPIStatus,
		"AgentEnrollmentProxyStatus":               agentEnrollmentProxyStatus,
		"AgentRelayCapability":                     agentRelayCapability,
		"AgentList":                                agentList,
		"EnrollmentTokenRequest":                   enrollmentTokenReq,
		"EnrollmentToken":                          enrollmentToken,
		"EnrollmentPlanPreview":                    enrollmentPlanPreview,
		"AgentCertRevocationRequest":               agentCertRevocationReq,
		"AgentCertRevocation":                      agentCertRevocation,
		"AgentOffboardRequest":                     agentOffboardReq,
		"AgentOffboardResponse":                    agentOffboardResp,
		"RiskComponents":                           riskComponents,
		"CredentialRisk":                           credentialRisk,
		"CredentialRiskList":                       credentialRiskList,
		"ContextualRiskSummary":                    contextualRiskSummary,
		"UrgentRiskProjectionSummary":              urgentRiskProjectionSummary,
		"UrgentRiskSummary":                        urgentRiskSummary,
		"ContextualRiskPriority":                   contextualRiskPriority,
		"ContextualRiskPriorities":                 contextualRiskPriorities,
		"CBOMScanRequest":                          cbomScanReq,
		"CBOMScanPreview":                          cbomScanPreview,
		"CBOMReport":                               cbomReport,
		"CBOMMigrationProgress":                    cbomMigrationProgress,
		"CBOMAsset":                                cbomAsset,
		"CBOMInventory":                            cbomInventory,
		"CBOMScan":                                 cbomScan,
		"IdentityIssuanceResult":                   identityIssuanceResult,
		"FirstIssuanceRetryRequest":                firstIssuanceRetryRequest,
		"FirstIssuanceRetry":                       firstIssuanceRetry,
		"IdentityDeploymentEvidence":               identityDeploymentEvidence,
		"Certificate":                              certificate,
		"CertificateIngest":                        certificateIngest,
		"CertificateList":                          list("Certificate"),
		"CertificateHealthSummary":                 certificateHealthSummary,
		"CertificateExpiryBucket":                  certificateExpiryBucket,
		"CertificateSourceHealth":                  certificateSourceHealth,
		"CertificateHealthItem":                    certificateHealthItem,
		"CertificateHealthDashboard":               certificateHealthDashboard,
		"RogueCertificateSummary":                  rogueCertificateSummary,
		"RogueCertificateFinding":                  rogueCertificateFinding,
		"RogueCertificatePosture":                  rogueCertificatePosture,
		"CRLDistributionShard":                     crlDistributionShard,
		"CRLDistribution":                          crlDistribution,
		"CRLDistributionList":                      list("CRLDistribution"),
		"CTLogSubmissionRequest":                   ctLogSubmissionReq,
		"CTLogSubmissionLog":                       ctLogSubmissionLog,
		"CTLogSubmissionNote":                      ctLogSubmissionNote,
		"CTLogSubmission":                          ctLogSubmission,
		"DiscoverySource":                          discoverySource,
		"DiscoverySourceRequest":                   discoverySourceReq,
		"DiscoverySourceList":                      list("DiscoverySource"),
		"DiscoveryCapabilityField":                 discoveryCapabilityField,
		"DiscoveryCapabilityProvider":              discoveryCapabilityProvider,
		"DiscoveryCapability":                      discoveryCapability,
		"DiscoveryCapabilityCatalog":               discoveryCapabilityCatalog,
		"DiscoveryPlanPreview":                     discoveryPlanPreview,
		"DiscoverySegment":                         discoverySegment,
		"DiscoverySegmentRequest":                  discoverySegmentReq,
		"DiscoverySchedule":                        discoverySchedule,
		"DiscoveryScheduleRequest":                 discoveryScheduleReq,
		"DiscoveryScheduleList":                    list("DiscoverySchedule"),
		"DiscoveryRun":                             discoveryRun,
		"DiscoveryRunRequest":                      discoveryRunReq,
		"DiscoveryRunList":                         list("DiscoveryRun"),
		"DiscoveryFinding":                         discoveryFinding,
		"DiscoveryFindingTriageRequest":            discoveryFindingTriageReq,
		"DiscoveryFindingList":                     list("DiscoveryFinding"),
		"DiscoveryMonitoringSummary":               discoveryMonitoringSummary,
		"DiscoveryMonitoringSource":                discoveryMonitoringSource,
		"DiscoveryMonitoring":                      discoveryMonitoring,
		"DiscoveryCoverage":                        discoveryCoverage,
		"ACMEUpstreamAuthorization":                acmeUpstreamAuthorization,
		"DeploymentTriState":                       deploymentTriState,
		"RenewalSLO":                               renewalSLO,
		"EndpointVerification":                     endpointVerification,
		"EndpointVerificationSummary":              endpointVerificationSummary,
		"EndpointVerificationList":                 endpointVerificationList,
		"RevocationEndpointHealth":                 revocationEndpointHealth,
		"RevocationHealthSummary":                  revocationHealthSummary,
		"RevocationHealth":                         revocationHealth,
		"RevocationCacheStatus":                    revocationCacheStatus,
		"RevocationCacheSummary":                   revocationCacheSummary,
		"RevocationCachePosture":                   revocationCachePosture,
		"EndpointKeyCustody":                       endpointKeyCustody,
		"EndpointCustodySummary":                   endpointCustodySummary,
		"EndpointKeyCustodyList":                   endpointKeyCustodyList,
		"ACMEUpstreamAuthorizationList":            acmeUpstreamAuthorizationList,
		"IssuerCapability":                         issuerCapability,
		"IssuerCapabilityMatrix":                   issuerCapabilityMatrix,
		"DiscoverySegmentCoverage":                 discoverySegmentCoverage,
		"DiscoveryProvenanceSummary":               discoveryProvenanceSummary,
		"DiscoveryUnknown":                         discoveryUnknown,
		"DiscoveryCoverageClass":                   discoveryCoverageClass,
		"CTMonitoringRequest":                      ctMonitoringReq,
		"CTMonitoringLog":                          ctMonitoringLog,
		"CTMonitoringSummary":                      ctMonitoringSummary,
		"CTMonitoring":                             ctMonitoring,
		"DriftRemediationDecisionRequest":          driftRemediationDecisionReq,
		"DriftRemediationSummary":                  driftRemediationSummary,
		"DriftRemediationFinding":                  driftRemediationFinding,
		"DriftRemediation":                         driftRemediation,
		"DriftRemediationDecision":                 driftRemediationDecision,
		"NHIInventoryItem":                         nhiInventoryItem,
		"NHIInventoryRecordSummary":                nhiInventoryRecordSummary,
		"NHIInventory":                             nhiInventory,
		"NHIShadowSummary":                         nhiShadowSummary,
		"NHIShadowFinding":                         nhiShadowFinding,
		"NHIShadowPosture":                         nhiShadowPosture,
		"NHIPolicyComplianceSummary":               nhiPolicyComplianceSummary,
		"NHIPolicyComplianceFinding":               nhiPolicyComplianceFinding,
		"NHIPolicyCompliance":                      nhiPolicyCompliance,
		"NHIOverPrivilegeSummary":                  nhiOverPrivilegeSummary,
		"NHIOverPrivilegeFinding":                  nhiOverPrivilegeFinding,
		"NHIOverPrivilegePosture":                  nhiOverPrivilegePosture,
		"NHIStaleThresholds":                       nhiStaleThresholds,
		"NHIStaleSummary":                          nhiStaleSummary,
		"NHIStaleFinding":                          nhiStaleFinding,
		"NHIStalePosture":                          nhiStalePosture,
		"NHIStaticThresholds":                      nhiStaticThresholds,
		"NHIStaticSummary":                         nhiStaticSummary,
		"NHIStaticFinding":                         nhiStaticFinding,
		"NHIStaticPosture":                         nhiStaticPosture,
		"NHIExposureSummary":                       nhiExposureSummary,
		"NHIExposureFinding":                       nhiExposureFinding,
		"NHIExposurePosture":                       nhiExposurePosture,
		"NHIDecommissionSignal":                    nhiDecommissionSignal,
		"NHIDecommissionRequest":                   nhiDecommissionRequest,
		"NHIDecommissionSummary":                   nhiDecommissionSummary,
		"NHIDecommissionItem":                      nhiDecommissionItem,
		"NHIDecommissionResponse":                  nhiDecommissionResponse,
		"OwnershipAttributionOwner":                ownershipAttributionOwner,
		"OwnershipAttributionItem":                 ownershipAttributionItem,
		"OwnershipAttribution":                     ownershipAttribution,
		"ACMEDNS01ProviderCatalogItem":             acmeDNS01ProviderCatalogItem,
		"ACMEDNS01ProviderCatalog":                 acmeDNS01ProviderCatalog,
		"ACMEDNS01ProviderConfigRequest":           acmeDNS01ProviderConfigReq,
		"ACMEDNS01ProviderConfig":                  acmeDNS01ProviderConfig,
		"ACMEDNS01ProviderConfigList":              acmeDNS01ProviderConfigList,
		"ACMEDNS01PreflightRequest":                acmeDNS01PreflightReq,
		"ACMEDNS01PreflightCheck":                  acmeDNS01PreflightCheck,
		"ACMEDNS01CAAPolicyRecord":                 acmeDNS01CAAPolicyRecord,
		"ACMEDNS01CAAPolicyEvidence":               acmeDNS01CAAPolicyEvidence,
		"ACMEDNS01Preflight":                       acmeDNS01Preflight,
		"ACMEDNS01QualificationRequest":            acmeDNS01QualificationReq,
		"ACMEDNS01QualificationCheck":              acmeDNS01QualificationCheck,
		"ACMEDNS01QualificationPreview":            acmeDNS01QualificationPreview,
		"ACMEDNS01QualificationRun":                acmeDNS01QualificationRun,
		"ACMEDNS01QualificationRunList":            acmeDNS01QualificationRunList,
		"ACMEARIWindow":                            acmeARIWindow,
		"ACMEARIPostureSummary":                    acmeARIPostureSummary,
		"ACMEARICertificatePosture":                acmeARICertificatePosture,
		"ACMEARIPosture":                           acmeARIPosture,
		"MDMSCEPPolicyRequest":                     mdmSCEPPolicyReq,
		"MDMSCEPPolicy":                            mdmSCEPPolicy,
		"MDMSCEPPolicyList":                        mdmSCEPPolicyList,
		"MDMSCEPPolicyPreview":                     mdmSCEPPolicyPreview,
		"MDMSCEPTelemetry":                         mdmSCEPTelemetry,
		"MDMSCEPStatus":                            mdmSCEPStatus,
		"MDMSCEPChallengeRotated":                  mdmSCEPChallengeRotated,
		"MDMSCEPChallengeRotationPreview":          mdmSCEPChallengeRotationPreview,
		"DRArtifactFailure":                        drArtifactFailure,
		"DRDrill":                                  drDrill,
		"DRPosture":                                drPosture,
		"EnrollmentDiagnostic":                     enrollmentDiagnostic,
		"EnrollmentDiagnosticList":                 enrollmentDiagnosticList,
		"EnrollmentDiagnosticVerification":         enrollmentDiagnosticVerification,
		"EnrollmentDiagnosticSupportAggregate":     enrollmentDiagnosticSupportAggregate,
		"EnrollmentDiagnosticsSupportAddendum":     enrollmentDiagnosticsSupportAddendum,
		"ConnectorSupportRow":                      connectorSupportRow,
		"ConnectorRelayParity":                     connectorRelayParity,
		"ConnectorCatalogItem":                     connectorCatalogItem,
		"RelayPluginGrant":                         relayPluginGrant,
		"RelayPluginEntry":                         relayPluginEntry,
		"RelayPluginRuntime":                       relayPluginRuntime,
		"ConnectorCatalog":                         connectorCatalog,
		"DeploymentTargetRequest":                  deploymentTargetReq,
		"DeploymentTarget":                         deploymentTarget,
		"DeploymentTargetList":                     list("DeploymentTarget"),
		"IdentityConnectorTargetRequest":           identityConnectorTargetReq,
		"EndpointIssuer":                           endpointIssuer,
		"EndpointBindingRequest":                   endpointBindingReq,
		"EndpointBindingPlanRequest":               endpointBindingPlanReq,
		"EndpointBindingTarget":                    endpointBindingTarget,
		"EndpointBindingCustody":                   endpointBindingCustody,
		"EndpointBindingPreview":                   endpointBindingPreview,
		"EndpointBinding":                          endpointBinding,
		"ConnectorTargetActionRequest":             connectorTargetActionReq,
		"ConnectorDelivery":                        connectorDelivery,
		"ConnectorDeliveryList":                    list("ConnectorDelivery"),
		"AlertRecipient":                           alertRecipient,
		"NotificationChannel":                      notificationChannel,
		"NotificationChannelList":                  list("NotificationChannel"),
		"NotificationChannelRequest":               notificationChannelReq,
		"NotificationChannelTestRequest":           notificationChannelTestReq,
		"NotificationChannelTest":                  notificationChannelTest,
		"NotificationDigestPreview":                notificationDigestPreview,
		"NotificationRoutingPolicyRequest":         notificationRoutingPolicyReq,
		"NotificationRoutingPolicy":                notificationRoutingPolicy,
		"NotificationRoutingPolicyList":            list("NotificationRoutingPolicy"),
		"NotificationRoutingPolicyPreview":         notificationRoutingPolicyPreview,
		"NotificationRoutingPreview":               notificationRoutingPreview,
		"Notification":                             notification,
		"NotificationDelivery":                     notificationDelivery,
		"NotificationList":                         list("Notification"),
		"PolicyDryRunRequest":                      policyDryRunReq,
		"PolicyDryRunTrace":                        policyDryRunTrace,
		"PolicyDryRunInputSummary":                 policyDryRunInputSummary,
		"PolicyDryRun":                             policyDryRun,
		"PolicyVersionRequest":                     policyVersionReq,
		"PolicyVersionActionRequest":               policyVersionActionReq,
		"PolicyVersion":                            policyVersion,
		"PolicyVersionListSummary":                 policyVersionListSummary,
		"PolicyVersionList":                        policyVersionList,
		"OutboxCircuit":                            outboxCircuit,
		"CodeSigningIdentity":                      codeSigningIdentity,
		"CodeSigningIdentityList":                  codeSigningIdentityList,
		"SSHFleetHost":                             sshFleetHost,
		"SSHFleetInventory":                        sshFleetInventory,
		"SystemDependency":                         systemDependency,
		"IdempotencyResultProtectionReadout":       idempotencyResultProtection,
		"TenantKeyDomainMigrateRequest":            tenantKeyDomainMigrateRequest,
		"TenantKeyDomainSealReceipt":               tenantKeyDomainSealReceipt,
		"TenantKeyDomainStatus":                    tenantKeyDomainStatus,
		"SystemReadout":                            systemReadout,
		"BulkheadPool":                             bulkheadPool,
		"BulkheadStats":                            bulkheadStats,
		"OutboxCircuitList":                        list("OutboxCircuit"),
		"RotationRun":                              rotationRun,
		"RotationRunList":                          list("RotationRun"),
		"LifecycleAutomationScheduler":             lifecycleAutomationScheduler,
		"LifecycleAutomationSummary":               lifecycleAutomationSummary,
		"LifecycleAutomationItem":                  lifecycleAutomationItem,
		"LifecycleAutomationControl":               lifecycleAutomationControl,
		"LifecycleAutomationPlan":                  lifecycleAutomationPlan,
		"IncidentExecutionRequest":                 incidentExecutionReq,
		"IncidentExecution":                        incidentExecution,
		"IncidentExecutionList":                    list("IncidentExecution"),
		"OutboxReconciliationConflict":             outboxReconciliationConflict,
		"OutboxReconciliationConflictList":         outboxReconciliationConflictList,
		"RemediationPlaybook":                      remediationPlaybook,
		"RemediationPlaybookCatalog":               remediationPlaybookCatalog,
		"RemediationPlaybookRunRequest":            remediationPlaybookRunReq,
		"RemediationPlaybookRun":                   remediationPlaybookRun,
		"RemediationPlaybookRunList":               list("RemediationPlaybookRun"),
		"OwnerRemediationSummary":                  ownerRemediationSummary,
		"OwnerRemediationAction":                   ownerRemediationAction,
		"OwnerRemediationQueue":                    ownerRemediationQueue,
		"OwnerRemediationAcceptRequest":            ownerRemediationAcceptReq,
		"OwnerRemediationRun":                      ownerRemediationRun,
		"FleetReissuanceHealthGate":                fleetHealthGate,
		"FleetReissuanceBatch":                     fleetBatch,
		"FleetReissuanceRequest":                   fleetReissuanceReq,
		"FleetReissuanceActionRequest":             fleetReissuanceActionReq,
		"FleetReissuanceRun":                       fleetReissuanceRun,
		"FleetReissuanceRunList":                   list("FleetReissuanceRun"),
		"FleetReissuanceEvidence":                  fleetReissuanceEvidence,
		"ServiceNowTicketRequest":                  serviceNowTicketReq,
		"ITSMTicket":                               itsmTicket,
		"ResponseIntegrationDestinationRequest":    responseIntegrationDestinationReq,
		"ResponseIntegrationDispatchRequest":       responseIntegrationDispatchReq,
		"ResponseIntegrationQueuedDestination":     responseIntegrationQueuedDestination,
		"ResponseIntegrationDispatch":              responseIntegrationDispatch,
		"Role":                                     role,
		"RoleList":                                 list("Role"),
		"OIDCTenantMapping":                        oidcTenantMapping,
		"OIDCMappingStatus":                        oidcMappingStatus,
		"Member":                                   member,
		"MemberRequest":                            memberReq,
		"MemberList":                               list("Member"),
		"OffboardMemberRequest":                    offboardMemberReq,
		"OffboardMemberResponse":                   offboardMemberResp,
		"APIToken":                                 apiToken,
		"APITokenList":                             list("APIToken"),
		"APITokenCreateRequest":                    apiTokenCreateReq,
		"APITokenCreateResponse":                   apiTokenCreateResp,
		"APITokenRevokeRequest":                    apiTokenRevokeReq,
		"AuditEvent":                               auditEvent,
		"AuditEventList":                           auditEventList,
		"AuditTimestampInfo":                       auditTimestampInfo,
		"AuditTimestampToken":                      auditTimestampToken,
		"AuditAnchor":                              auditAnchor,
		"AuditBundle":                              auditBundle,
		"AuditVerificationKeySet":                  auditVerificationKeySet,
		"AuditFeedRequest":                         auditFeedRequest,
		"AuditFeed":                                auditFeed,
		"AuditFeedPreview":                         auditFeedPreview,
		"AuditFeedList":                            auditFeedList,
		"ComplianceEvidencePack":                   complianceEvidencePack,
		"CertificateCustodySummary":                certificateCustodySummary,
		"CustodyOriginCounts":                      custodyOriginCounts,
		"CustodyStorageCounts":                     custodyStorageCounts,
		"CustodyExportabilityCounts":               custodyExportabilityCounts,
		"UnrecordedCustodyCertificate":             unrecordedCustodyCertificate,
		"ComplianceReportScheduleRequest":          complianceReportScheduleReq,
		"ComplianceReportSchedulePreview":          complianceReportSchedulePreview,
		"ComplianceReportSchedule":                 complianceReportSchedule,
		"ComplianceReportScheduleList":             list("ComplianceReportSchedule"),
		"ComplianceInventorySummary":               complianceInventorySummary,
		"ComplianceInventoryReport":                complianceInventoryReport,
		"NHIComplianceSummary":                     nhiComplianceSummary,
		"NHIComplianceFramework":                   nhiComplianceFramework,
		"NHIComplianceControl":                     nhiComplianceControl,
		"NHIComplianceReport":                      nhiComplianceReport,
		"PrivacySubjectErasureRequest":             privacyErasureReq,
		"PrivacySubjectErasurePreview":             privacySubjectErasurePreview,
		"PrivacyErasureSelectors":                  privacyErasureSelectors,
		"PrivacySubjectErasure":                    privacySubjectErasure,
		"PrivacySubjectErasureList":                list("PrivacySubjectErasure"),
		"PrivacyRetentionCutoffs":                  privacyRetentionCutoffs,
		"PrivacyRetentionRun":                      privacyRetentionRun,
		"PrivacyRetentionPreview":                  privacyRetentionPreview,
		"PrivacyRetentionRunList":                  list("PrivacyRetentionRun"),
		"PrivacyArchiveErasureAttestationRequest":  privacyArchiveErasureReq,
		"PrivacyArchiveErasureAttestation":         privacyArchiveErasure,
		"PrivacyArchiveErasureAttestationList":     list("PrivacyArchiveErasureAttestation"),
		"PrivacyCatalogEntry":                      privacyCatalogEntry,
		"PrivacyCatalog":                           privacyCatalog,
		"PrivacySubjectExportRequest":              privacySubjectExportReq,
		"PrivacySubjectExport":                     privacySubjectExport,
		"Attestation":                              attestation,
		"AttestedSVIDRequest":                      attestedSVIDReq,
		"AttestedSVIDPreview":                      attestedSVIDPreview,
		"AttestedSVID":                             attestedSVID,
		"WorkloadAttesterTrustSourceRequest":       workloadAttesterTrustSourceReq,
		"WorkloadAttesterTrustSourceRotateRequest": workloadAttesterTrustSourceRotateReq,
		"WorkloadAttesterTrustSourceRevokeRequest": workloadAttesterTrustSourceRevokeReq,
		"WorkloadAttesterTrustSource":              workloadAttesterTrustSource,
		"WorkloadAttesterTrustSourceList":          list("WorkloadAttesterTrustSource"),
		"WorkloadAttesterTrustSourceRotated":       workloadAttesterTrustSourceRotated,
		"WorkloadAttesterTrustSourceRevoked":       workloadAttesterTrustSourceRevoked,
		"SecretSyncWorkloadIdentitySourceRequest":  secretSyncWorkloadIdentitySourceReq,
		"SecretSyncWorkloadIdentitySource":         secretSyncWorkloadIdentitySource,
		"SecretSyncWorkloadIdentitySourceList":     list("SecretSyncWorkloadIdentitySource"),
		"SSHStatus":                                sshStatus,
		"SSHTrustRolloutRequest":                   sshTrustRolloutReq,
		"SSHTrustRollout":                          sshTrustRollout,
		"SSHCertificateRequest":                    sshCertificateReq,
		"SSHCertificatePreview":                    sshCertificatePreview,
		"SSHCertificate":                           sshCertificate,
		"SSHAttestedUserCertRequest":               sshAttestedUserCertReq,
		"SSHAttestedUserCertPreview":               sshAttestedUserCertPreview,
		"SSHAttestedUserCert":                      sshAttestedUserCert,
		"SSHRevokeCertificateRequest":              sshRevokeCertReq,
		"SSHHostRetireRequest":                     sshHostRetireReq,
		"SSHHostRetirement":                        sshHostRetirement,
		"BrokerAgentIdentityRequest":               brokerAgentIdentityReq,
		"BrokerAgentIdentityPreview":               brokerAgentIdentityPreview,
		"BrokerIssuanceFacts":                      brokerIssuanceFacts,
		"BrokerAgentIdentityHistory":               brokerIdentityHistory,
		"BrokerAgentIdentityHistoryList":           brokerIdentityHistoryList,
		"BrokerAgentIdentity":                      brokerAgentIdentity,
		"EphemeralCredentialRequest":               ephemeralCredentialReq,
		"EphemeralCredentialPreview":               ephemeralCredentialPreview,
		"EphemeralCredential":                      ephemeralCredential,
		"EphemeralAPIKeyRequest":                   ephemeralAPIKeyReq,
		"EphemeralAPIKeyPreview":                   ephemeralAPIKeyPreview,
		"EphemeralAPIKey":                          ephemeralAPIKey,
		"EphemeralApprovalRequest":                 ephemeralApprovalReq,
		"EphemeralApproval":                        ephemeralApproval,
		"PAMSessionRequest":                        pamSessionReq,
		"PAMSession":                               pamSession,
		"PAMSessionList":                           list("PAMSession"),
		"PAMPostgresCredential":                    pamPostgresCredential,
		"PAMSSHCredential":                         pamSSHCredential,
		"GraphNode":                                graphNode,
		"GraphEdge":                                graphEdge,
		"GraphEvidencePath":                        graphEvidencePath,
		"GraphResponse":                            graphResponse,
		"GraphReachable":                           graphReachable,
		"GraphImpact":                              graphImpact,
		"OwnershipImportResult":                    ownershipImportResult,
		"OwnershipConflictList":                    ownershipConflictList,
		"OwnershipResolveInput":                    ownershipResolveInput,
		"CMDBReconcileSchedule":                    cmdbReconcileSchedule,
		"IssuanceRequest":                          issuanceRequestSchema,
		"Brand":                                    brandSchema,
		"AgentUpgradeCampaign":                     agentUpgradeCampaignSchema,
		"AgentUpgradeCampaignInput":                agentUpgradeCampaignInput,
		"UpgradeArtifact":                          upgradeArtifactSchema,
		"AgentRingInput":                           agentRingInput,
		"MDMDevice":                                mdmDeviceSchema,
		"MDMDeviceList":                            mdmDeviceListSchema,
		"MDMPollSchedule":                          mdmPollScheduleSchema,
		"MDMPollScheduleInput":                     mdmPollScheduleInput,
		"MDMPollScheduleList":                      mdmPollScheduleList,
		"ADCSDatabaseSummary":                      adcsDatabaseSummarySchema,
		"ADCSDatabaseIngest":                       adcsDatabaseIngestSchema,
		"ADCSDatabaseList":                         adcsDatabaseListSchema,
		"TicketIntakeSchedule":                     ticketIntakeSchema,
		"TicketIntakeInput":                        ticketIntakeInput,
		"EdgeSegmentPolicy":                        edgeSegmentPolicySchema,
		"EdgeSegmentPolicyInput":                   edgeSegmentPolicyInput,
		"EdgeSegmentPolicyList":                    edgeSegmentPolicyList,
		"EdgeDelegation":                           edgeDelegationSchema,
		"EdgeDelegationMintInput":                  edgeDelegationMintInput,
		"EdgeDelegationList":                       edgeDelegationList,
		"EdgeIssuance":                             edgeIssuanceSchema,
		"EdgeDelegationDetail":                     edgeDelegationDetailSchema,
		"EdgeDelegationRevokeInput":                edgeDelegationRevokeInput,
		"EdgeReconcileInput":                       edgeReconcileInput,
		"EdgeReconcileResult":                      edgeReconcileResultSchema,
		"MDMTraceStep":                             mdmTraceStepSchema,
		"MDMDeviceTrace":                           mdmDeviceTraceSchema,
		"IssuanceRequestInput":                     issuanceRequestInput,
		"IssuanceRequestPreview":                   issuanceRequestPreview,
		"IssuanceDecisionInput":                    issuanceDecisionInput,
		"IssuanceRequestList":                      issuanceRequestListSchema,
		"IssuanceRequestPreparation":               issuanceRequestPreparation,
		"OwnershipConflict":                        ownershipConflictSchema,
		"CryptoReadiness":                          cryptoReadiness,
		"CryptoReadinessRow":                       cryptoReadinessRow,
		"CryptoReadinessAction":                    cryptoReadinessAction,
		"CryptoReadinessExport":                    cryptoReadinessExport,
		"CryptoDependent":                          cryptoDependent,
		"GraphTrustStores":                         graphTrustStores,
		"UnownedIdentity":                          unownedIdentity,
		"UnownedQueue":                             unownedQueue,
		"RetirementDependent":                      retirementDependent,
		"RetirementChecklist":                      retirementChecklist,
		"MigrationAssessRequest":                   migrationAssessRequest,
		"MigrationUnknown":                         migrationUnknown,
		"MigrationAssessedWave":                    migrationAssessedWave,
		"MigrationAssessment":                      migrationAssessment,
		"MigrationRunStartMember":                  migrationRunStartMember,
		"MigrationRunStartWave":                    migrationRunStartWave,
		"MigrationRunStartRequest":                 migrationRunStartRequest,
		"MigrationMemberBinding":                   migrationMemberBinding,
		"MigrationRunMember":                       migrationRunMember,
		"MigrationRunWave":                         migrationRunWave,
		"MigrationRun":                             migrationRun,
		"MigrationRunList":                         list("MigrationRun"),
		"MigrationRunActionRequest":                migrationRunActionRequest,
		"GraphQueryResult":                         graphQueryResult,
		"Owner":                                    owner,
		"OwnerRequest":                             ownerReq,
		"OwnerList":                                list("Owner"),
		"OwnershipAssignmentRequest":               ownershipAssignmentReq,
		"OwnershipAssignmentResult":                ownershipAssignmentResult,
		"OwnershipException":                       ownershipException,
		"OwnershipExceptionRequest":                ownershipExceptionReq,
		"OwnershipExceptionRevokeRequest":          ownershipExceptionRevokeReq,
		"OwnershipExceptionList":                   list("OwnershipException"),
		"Profile":                                  profile,
		"ProfileRequest":                           profileReq,
		"ProfileList":                              list("Profile"),
		"ProfileApprovalResponse":                  profileApproval,
		"ProfileEditApprovalDecision":              profileEditApprovalDecision,
		"ProfileEditApprovalRecord":                profileEditApprovalRecord,
		"ProfileEditApprovalList":                  list("ProfileEditApprovalRecord"),
		"ProfileEditApprovalDecisionRequest":       profileEditApprovalDecisionReq,
		"ProfileRestoreRequest":                    profileRestoreReq,
		"ProfileRestorePreview":                    profileRestorePreview,
		"CertificateProfileSpec":                   certificateProfileSpec,
		"ACMEDeviceAttestationPolicy":              acmeDeviceAttestationPolicy,
		"Issuer":                                   issuer,
		"IssuerRequest":                            issuerReq,
		"IssuerList":                               list("Issuer"),
		"ProtocolProfileStatus":                    protocolProfileStatus,
		"CMPQualificationCheck":                    cmpQualificationCheck,
		"CMPQualification":                         cmpQualification,
		"TSAQualificationCheck":                    tsaQualificationCheck,
		"TSAQualification":                         tsaQualification,
		"SPIFFEQualificationCheck":                 spiffeQualificationCheck,
		"SPIFFEQualification":                      spiffeQualification,
		"CASpec":                                   caSpec,
		"CACeremonyStartRequest":                   caCeremonyStartReq,
		"CAKeyCeremony":                            caCeremony,
		"CACeremonyPlanAuthority":                  caCeremonyPlanAuthority,
		"CACeremonyPlanPreview":                    caCeremonyPlanPreview,
		"CACreateRootRequest":                      caCreateRootReq,
		"CAImportOfflineRootRequest":               caImportOfflineRootReq,
		"CAImportExistingRequest":                  caImportExistingReq,
		"CACreateIntermediateRequest":              caCreateIntermediateReq,
		"CACreateOfflineIntermediateCSRRequest":    caCreateOfflineIntermediateCSRReq,
		"CAImportOfflineIntermediateRequest":       caImportOfflineIntermediateReq,
		"CAIntermediateCSR":                        caIntermediateCSR,
		"CAIssueIntermediateRequest":               caIssueIntermediateReq,
		"CAAuthorityRotationRequest":               caAuthorityRotationReq,
		"CAAuthorityRekeyRequest":                  caAuthorityRekeyReq,
		"CACrossSignRequest":                       caCrossSignReq,
		"CAOfflineCrossSignImportRequest":          caOfflineCrossSignImportReq,
		"CAOfflineRootRekeyRequest":                caOfflineRootRekeyReq,
		"CAAuthorityRotationIssuer":                caAuthorityRotationIssuer,
		"CAAuthorityRotation":                      caAuthorityRotation,
		"CAAuthorityRotationPlanPreview":           caAuthorityRotationPlanPreview,
		"CACrossSign":                              caCrossSign,
		"CAOfflineRootRekey":                       caOfflineRootRekey,
		"CAAuthority":                              caAuthority,
		"CAAuthorityHorizon":                       caAuthorityHorizon,
		"ACMEEABCredential":                        acmeEABCredential,
		"ACMEEABPosture":                           acmeEABPosture,
		"ACMEOperatorAction":                       acmeOperatorAction,
		"ACMEDomainValidationActivity":             acmeDomainValidationActivity,
		"ACMEOperatorPlan":                         acmeOperatorPlan,
		"AgentJobQueue":                            agentJobQueue,
		"AgentJobPosture":                          agentJobPosture,
		"AgentJobRedemptions":                      agentJobRedemptions,
		"AgentJobReceipts":                         agentJobReceipts,
		"ADCSPosture":                              adcsPosture,
		"ADCSInventorySource":                      adcsInventorySource,
		"ADCSTemplate":                             adcsTemplate,
		"ADCSEnrollmentEndpoint":                   adcsEnrollmentEndpoint,
		"ADCSEnrollmentService":                    adcsEnrollmentService,
		"ADCSObservedTemplate":                     adcsObservedTemplate,
		"ADCSAgentRestrictions":                    adcsAgentRestrictions,
		"ADCSObservedService":                      adcsObservedService,
		"ADCSRuleFinding":                          adcsRuleFinding,
		"ADCSAuditReference":                       adcsAuditReference,
		"ADCSObservedInventory":                    adcsObservedInventory,
		"ADCSComplianceObservation":                adcsComplianceObservation,
		"ADCSComplianceDrift":                      adcsComplianceDrift,
		"ADCSComplianceEvidence":                   adcsComplianceEvidence,
		"ADCSTemplateFinding":                      adcsTemplateFinding,
		"ADCSFindingEvidence":                      adcsFindingEvidence,
		"ADCSDriftHistory":                         adcsDriftHistory,
		"ADCSTemplateDrift":                        adcsTemplateDrift,
		"ADCSTemplateDriftChange":                  adcsTemplateDriftChange,
		"ADCSTemplateLifecycleChange":              adcsTemplateLifecycleChange,
		"CAAuthorityList":                          list("CAAuthority"),
		"CADiscoveryItem":                          caDiscoveryItem,
		"CADiscoverySummary":                       caDiscoverySummary,
		"CADiscoveryInventory":                     caDiscoveryInventory,
		"CAIssueLeafRequest":                       caIssueLeafReq,
		"CAIssuedIntermediate":                     caIssuedIntermediate,
		"CAIssuedLeaf":                             caIssuedLeaf,
		"ExternalCA":                               externalCA,
		"ExternalCAList":                           list("ExternalCA"),
		"ExternalCAIssueRequest":                   externalCAIssueReq,
		"ExternalCAIssuedCertificate":              externalCAIssued,
		"Identity":                                 identity,
		"IdentityRequest":                          identityReq,
		"IdentityList":                             list("Identity"),
		"TransitionRequest":                        transitionReq,
		"IdentityTransitionPreview":                identityTransitionPreview,
		"BulkRevokeRequest":                        bulkRevokeReq,
		"BulkRevokeItem":                           bulkRevokeItem,
		"BulkRevokeResult":                         bulkRevokeResult,
		"ApprovalRequest":                          approvalReq,
		"Approval":                                 approval,
		"PendingApprovalRequest":                   approvalRequestRecord,
		"ApprovalRequestList":                      approvalRequestList,
		"ApprovalDecisionInput":                    approvalDecisionInput,
		"ApprovalDenialInput":                      approvalDenialInput,
		"ApprovalDecision":                         approvalDecision,
		"SecretApprovalRequest":                    secretApprovalReq,
		"SecretApproval":                           secretApproval,
		"BreakglassBundle":                         breakglassBundle,
		"BreakglassIssueRequest":                   breakglassLegacyIssueReq,
		"BreakglassIssueIntentRequest":             breakglassIssueIntentReq,
		"BreakglassIssueExecutionRequest":          breakglassIssueExecutionReq,
		"BreakglassPrerequisite":                   breakglassPrerequisite,
		"BreakglassIssuePlanPreview":               breakglassIssuePlanPreview,
		"BreakglassIssueResponse":                  breakglassIssueResp,
		"BreakglassCeremony":                       breakglassCeremony,
		"BreakglassRotationIntent":                 breakglassRotationIntent,
		"BreakglassRotationRequest":                breakglassRotationReq,
		"BreakglassRotation":                       breakglassRotation,
		"BreakglassCrossSignRequest":               breakglassCrossSignReq,
		"BreakglassCrossSign":                      breakglassCrossSign,
		"BreakglassReconcileRequest":               breakglassReconcileReq,
		"BreakglassReconcileResponse":              breakglassReconcileResp,
		"SecretCreateRequest":                      secretCreateReq,
		"SecretStoreCreatePreview":                 secretStoreCreatePreview,
		"SecretAccessPreviewRequest":               secretAccessPreviewReq,
		"SecretAccessPreview":                      secretAccessPreview,
		"SecretRotateRequest":                      secretRotateReq,
		"SecretImportRequest":                      secretImportReq,
		"SecretRecoverRequest":                     secretRecoverReq,
		"SecretMeta":                               secretMeta,
		"MachineAuthMethod": object(map[string]*Schema{
			"name": str(), "type": str(), "source": str(),
			"issuer": str(), "audience": str(), "tenant_claim": str(), "subject_claim": str(),
			"scopes_claim": str(), "principal_prefix": str(),
			"scopes":                   {Type: "array", Items: str()},
			"scopes_by_principal":      {Type: "object", AdditionalProperties: &Schema{Type: "array", Items: str()}},
			"allowed_namespaces":       {Type: "array", Items: str()},
			"allowed_service_accounts": {Type: "array", Items: str()},
			"allowed_projects":         {Type: "array", Items: str()},
			"allowed_azure_tenants":    {Type: "array", Items: str()},
			"allowed_accounts":         {Type: "array", Items: str()},
			"allowed_arns":             {Type: "array", Items: str()},
			"required_claims":          {Type: "object", AdditionalProperties: str()},
			"jwks_configured":          {Type: "boolean"},
			"allow_unexpiring":         {Type: "boolean"},
			"disabled":                 {Type: "boolean"},
		}, "name", "type", "source", "jwks_configured"),
		"MachineAuthMethodList": list("MachineAuthMethod"),
		"MachineSession": object(map[string]*Schema{
			"id": str(), "principal": str(), "method": str(),
			"scopes":     {Type: "array", Items: str()},
			"status":     {Type: "string", Enum: []string{"active", "expired", "revoked"}},
			"issued_at":  timestamp(),
			"expires_at": timestamp(),
			"revoked_at": timestamp(),
			"revoked_by": str(),
		}, "id", "principal", "method", "status", "issued_at", "expires_at"),
		"MachineSessionList": list("MachineSession"),
		"MachineAuthMethodOverride": object(map[string]*Schema{
			"name":     str(),
			"disabled": {Type: "boolean"},
		}, "name", "disabled"),
		"MachineLoginPreviewRequest":         machineLoginPreviewReq,
		"MachineLoginPrerequisite":           machineLoginPrerequisite,
		"MachineLoginPreview":                machineLoginPreview,
		"SecretMetaList":                     list("SecretMeta"),
		"SecretValue":                        secretValue,
		"SecretRotationRequest":              secretRotationReq,
		"SecretRotation":                     secretRotation,
		"SecretRotationPreview":              secretRotationPreview,
		"SecretRotationScheduleRequest":      secretRotationScheduleReq,
		"SecretRotationSchedule":             secretRotationSchedule,
		"SecretRotationScheduleList":         list("SecretRotationSchedule"),
		"SecretRotationScheduleRun":          secretRotationScheduleRun,
		"SecretRotationScheduleDeferred":     secretRotationScheduleDeferred,
		"SecretRotationDueRun":               secretRotationDueRun,
		"SecretSyncRequest":                  secretSyncReq,
		"SecretSyncPreview":                  secretSyncPreview,
		"SecretSync":                         secretSync,
		"SecretSyncTarget":                   secretSyncTarget,
		"SecretSyncTargetCatalog":            secretSyncTargetCatalog,
		"CloudSecretManagerProvider":         cloudSecretManagerProvider,
		"CloudSecretManagerSummary":          cloudSecretManagerSummary,
		"CloudSecretManagerIntegration":      cloudSecretManagerIntegration,
		"KubernetesSecretOperatorCRD":        kubernetesSecretOperatorCRD,
		"KubernetesSecretOperator":           kubernetesSecretOperator,
		"SecretWorkloadInjectionCRD":         secretWorkloadInjectionCRD,
		"SecretWorkloadInjectionMode":        secretWorkloadInjectionMode,
		"SecretWorkloadInjection":            secretWorkloadInjection,
		"UnvaultedSecretSummary":             unvaultedSecretSummary,
		"UnvaultedSecretDetectionSource":     unvaultedSecretDetectionSource,
		"UnvaultedSecretVaultProvider":       unvaultedSecretVaultProvider,
		"UnvaultedSecretPosture":             unvaultedSecretPosture,
		"KubernetesPostureSummary":           kubernetesPostureSummary,
		"KubernetesPostureController":        kubernetesPostureController,
		"KubernetesPostureObject":            kubernetesPostureObject,
		"KubernetesCSRSupportRule":           kubernetesCSRSupportRule,
		"KubernetesCSRSupport":               kubernetesCSRSupport,
		"KubernetesTrustBundleDistribution":  kubernetesTrustBundleDistribution,
		"SecretScanRequest":                  secretScanReq,
		"SecretScanPreview":                  secretScanPreview,
		"SecretScanFinding":                  secretScanFinding,
		"SecretScan":                         secretScan,
		"SecretRepositoryScanProvider":       secretRepoProvider,
		"SecretRepositoryScanGate":           secretRepoGate,
		"SecretRepositoryScanPosture":        secretRepoPosture,
		"SecretRepositoryWebhookRequest":     secretRepoWebhookReq,
		"SecretRepositoryWebhookReceipt":     secretRepoWebhookReceipt,
		"ThirdPartySecretScanProvider":       thirdPartySecretScanProvider,
		"ThirdPartySecretScanPosture":        thirdPartySecretScanPosture,
		"ThirdPartySecretScanIngestRequest":  thirdPartySecretScanIngestReq,
		"ThirdPartySecretScanReceipt":        thirdPartySecretScanReceipt,
		"DynamicLeaseRequest":                dynamicLeaseReq,
		"DynamicSecretProviderRequirement":   dynamicSecretRequirement,
		"DynamicSecretSupportedProvider":     dynamicSecretSupportedProvider,
		"DynamicSecretConfiguredProvider":    dynamicSecretConfiguredProvider,
		"DynamicSecretProviderCatalog":       dynamicSecretProviderCatalog,
		"DynamicLeasePreview":                dynamicLeasePreview,
		"DynamicLeaseRenewRequest":           dynamicLeaseRenewReq,
		"DynamicLease":                       dynamicLease,
		"TransitKeyRequest":                  transitKeyReq,
		"TransitRotateRequest":               transitRotateReq,
		"TransitKey":                         transitKey,
		"TransitKeyList":                     transitKeyList,
		"TransitKeyVersion":                  transitKeyVersion,
		"TransitKeyVersionList":              transitKeyVersionList,
		"TransitServicePosture":              transitServicePosture,
		"KMIPPosture":                        kmipPosture,
		"TransitPosture":                     transitPosture,
		"TransitEncryptRequest":              transitEncryptReq,
		"TransitDecryptRequest":              transitCiphertextReq,
		"TransitRewrapRequest":               transitCiphertextReq,
		"TransitCiphertext":                  transitCiphertext,
		"TransitPlaintext":                   transitPlaintext,
		"TransitHMACRequest":                 transitHMACReq,
		"TransitHMAC":                        transitHMAC,
		"TransitSignRequest":                 transitSignReq,
		"TransitSignature":                   transitSignature,
		"TransitVerifyRequest":               transitVerifyReq,
		"TransitVerify":                      transitVerify,
		"CodeSigningRequest":                 codeSigningReq,
		"CodeSigningKeylessRequest":          codeSigningKeylessReq,
		"CodeSigningPreview":                 codeSigningPreview,
		"CodeSigningSignature":               codeSigningSignature,
		"ManagedKeyCustodyRequirement":       managedKeyCustodyRequirement,
		"ManagedKeyCustodyProvider":          managedKeyCustodyProvider,
		"ManagedKeyCustodyPlan":              managedKeyCustodyPlan,
		"ManagedKeyGenerationPreviewRequest": managedKeyGenerationPreviewReq,
		"ManagedKeyGenerationPreview":        managedKeyGenerationPreview,
		"ManagedKeyGenerateRequest":          managedKeyGenerateReq,
		"ManagedKeyActionRequest":            managedKeyActionReq,
		"ManagedKeyApprovalRequest":          managedKeyApprovalReq,
		"ManagedKeyApproval":                 managedKeyApproval,
		"ManagedKey":                         managedKey,
		"ShareRequest":                       shareReq,
		"SharePreviewRequest":                sharePreviewReq,
		"SharePreview":                       sharePreview,
		"ShareToken":                         shareToken,
		"ShareRedeemRequest":                 shareRedeemReq,
		"ShareValue":                         shareValue,
		"PKISecretRequest":                   pkiSecretReq,
		"PKISecretPrerequisite":              pkiSecretPrerequisite,
		"PKISecretPreview":                   pkiSecretPreview,
		"PKISecret":                          pkiSecret,
		"MachineLoginRequest":                machineLoginReq,
		"MachineLoginResponse":               machineLoginResp,
		"AIQueryRequest":                     aiQueryReq,
		"RCARequest":                         rcaReq,
		"AIAnswer":                           aiAnswer,
		"AIStatus":                           aiStatus,
		"MCPToolList":                        mcpToolList,
		"MCPToolCall":                        mcpToolCall,
		"MCPToolResult":                      mcpToolResult,
		"EditionFeature":                     editionFeature,
		"EditionPackaging":                   editionPackaging,
		"EditionPackagingEntry":              editionPackagingEntry,
		"ReferencePriceBand":                 referencePriceBand,
		"DeploymentEntitlementInfo":          deploymentEntitlementInfo,
		"FIPSAlgorithmMode":                  fipsAlgorithmMode,
		"FIPSNonFIPSFence":                   fipsNonFIPSFence,
		"FIPSCustodyValidationCertificate":   fipsCustodyValidationCertificate,
		"FIPSRegulatedDeploymentProfile":     fipsRegulatedDeploymentProfile,
		"FIPSStatus":                         fipsStatus,
		"EditionsInfo":                       editionsInfo,
		"UsageMeterDefinition":               usageMeterDefinition,
	}
}

// openapiHandler serves the generated OpenAPI 3.1 document.
func (a *API) openapiHandler(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.spec)
}

// Spec returns the generated OpenAPI document. It is exported so the golden-contract
// test (SCHEMA-004) can diff the served spec against a checked-in baseline and the
// breaking-change assertions can inspect it without going over HTTP.
func (a *API) Spec() *Document { return a.spec }
