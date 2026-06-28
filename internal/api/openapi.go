package api

import (
	"net/http"
	"strings"
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
	Parameters         []Parameter           `json:"parameters,omitempty"`
	RequestBody        *RequestBody          `json:"requestBody,omitempty"`
	Responses          map[string]Response   `json:"responses"`
	Security           []map[string][]string `json:"security,omitempty"`
	XPermission        string                `json:"x-trstctl-permission,omitempty"`
	XPublicRationale   string                `json:"x-trstctl-public-rationale,omitempty"`
	XSensitiveResponse bool                  `json:"x-trstctl-sensitive-response,omitempty"`
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
	Ref        string             `json:"$ref,omitempty"`
	Type       string             `json:"type,omitempty"`
	Format     string             `json:"format,omitempty"`
	Items      *Schema            `json:"items,omitempty"`
	Properties map[string]*Schema `json:"properties,omitempty"`
	Required   []string           `json:"required,omitempty"`
	Enum       []string           `json:"enum,omitempty"`
}

func ref(name string) *Schema { return &Schema{Ref: "#/components/schemas/" + name} }

func str() *Schema       { return &Schema{Type: "string"} }
func uuid() *Schema      { return &Schema{Type: "string", Format: "uuid"} }
func timestamp() *Schema { return &Schema{Type: "string", Format: "date-time"} }

// buildSpec generates the OpenAPI document from the route registry. The spec
// endpoint itself is omitted from the documented paths.
func buildSpec(routes []route) *Document {
	doc := &Document{
		OpenAPI: "3.1.0",
		Info: Info{
			Title:       "trstctl API",
			Version:     "v1",
			Description: "Resource-oriented REST API for trstctl. Mutations require an Idempotency-Key; errors are RFC 7807 problem+json; lists use cursor pagination.",
		},
		Paths: map[string]PathItem{},
		Components: Components{
			Schemas: componentSchemas(),
			SecuritySchemes: map[string]SecurityScheme{
				"BearerAuth": {
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
		for _, pp := range r.pathParams {
			op.Parameters = append(op.Parameters, Parameter{Name: pp.name, In: "path", Required: true, Description: pp.desc, Schema: schemaForParam(pp)})
		}
		for _, q := range r.query {
			op.Parameters = append(op.Parameters, Parameter{Name: q.name, In: "query", Description: q.desc, Schema: schemaForParam(q)})
		}
		if r.reqSchema != "" {
			op.RequestBody = &RequestBody{Required: true, Content: map[string]MediaType{
				"application/json": {Schema: ref(r.reqSchema)},
			}}
		}
		success := Response{Description: "success"}
		if r.resSchema != "" {
			success.Content = map[string]MediaType{"application/json": {Schema: ref(r.resSchema)}}
		}
		op.Responses[r.successCode] = success
		problemContent := map[string]MediaType{"application/problem+json": {Schema: ref("Problem")}}
		op.Responses["4XX"] = Response{Description: "client error", Content: problemContent}
		op.Responses["5XX"] = Response{Description: "server error", Content: problemContent}
		pi[strings.ToLower(r.method)] = op
	}
	return doc
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
	owner := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: []string{"user", "team", "workload", "service"}},
		"name": str(), "email": str(), "created_at": timestamp(),
	}, "id", "tenant_id", "kind", "name")
	ownerReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: []string{"user", "team", "workload", "service"}}, "name": str(), "email": str(),
	}, "kind", "name")

	issuer := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: []string{"x509_ca", "ssh_ca"}},
		"name": str(), "chain": {Type: "array", Items: str()}, "public_key": str(),
		"internal": {Type: "boolean"}, "chainless": {Type: "boolean"}, "created_at": timestamp(),
	}, "id", "kind", "name")
	issuerReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: []string{"x509_ca", "ssh_ca"}}, "name": str(),
		"chain": {Type: "array", Items: str()}, "public_key": str(), "internal": {Type: "boolean"},
	}, "kind", "name")

	caSpec := object(map[string]*Schema{
		"common_name":           str(),
		"permitted_dns_domains": {Type: "array", Items: str()},
		"max_path_len":          {Type: "integer"},
		"extended_key_usages":   {Type: "array", Items: str()},
		"ttl_seconds":           {Type: "integer"},
		"signature_algorithm":   str(),
	}, "common_name")
	caCeremonyStartReq := object(map[string]*Schema{
		"operation": {Type: "string", Enum: []string{"create_root", "import_offline_root", "import_existing_ca", "create_intermediate", "create_offline_intermediate", "issue_intermediate_csr"}},
		"parent_id": uuid(), "csr_pem": str(), "certificate_pem": str(), "signer_handle": str(), "threshold": {Type: "integer"}, "spec": ref("CASpec"),
	}, "operation", "threshold", "spec")
	caCeremony := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "purpose": str(), "threshold": {Type: "integer"},
		"status": str(), "approvals": {Type: "integer"}, "opener": str(), "created_at": timestamp(),
	}, "id", "tenant_id", "purpose", "threshold", "status", "approvals", "created_at")
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
	caIntermediateCSR := object(map[string]*Schema{
		"ceremony_id": uuid(), "parent_id": uuid(), "csr_pem": str(), "signer_handle": str(),
	}, "ceremony_id", "parent_id", "csr_pem", "signer_handle")
	caAuthority := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "parent_id": uuid(), "common_name": str(),
		"kind": str(), "status": str(), "certificate_pem": str(), "signer_handle": str(),
		"serial": str(), "not_after": timestamp(), "max_path_len": {Type: "integer"},
		"permitted_dns_names": {Type: "array", Items: str()},
		"extended_key_usages": {Type: "array", Items: str()},
		"created_at":          timestamp(),
	}, "id", "tenant_id", "common_name", "kind", "status", "certificate_pem", "signer_handle", "serial", "max_path_len", "created_at")
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

	transitionReq := object(map[string]*Schema{
		"to":     {Type: "string", Enum: []string{"issued", "deployed", "renewing", "revoked", "retired"}},
		"reason": str(),
	}, "to")
	revocationReasons := []string{"unspecified", "keyCompromise", "caCompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aaCompromise"}
	bulkRevokeReq := object(map[string]*Schema{
		"ids":             {Type: "array", Items: uuid()},
		"identity_ids":    {Type: "array", Items: uuid()},
		"certificate_ids": {Type: "array", Items: uuid()},
		"owner_id":        uuid(),
		"issuer_id":       uuid(),
		"kind":            {Type: "string", Enum: identityKinds},
		"status":          {Type: "string", Enum: []string{"requested", "issued", "deployed", "renewing", "revoked", "retired"}},
		"reason":          {Type: "string", Enum: revocationReasons},
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

	approvalReq := object(map[string]*Schema{
		"action": {Type: "string", Enum: []string{"issue", "revoke"}},
	}, "action")
	approval := object(map[string]*Schema{
		"resource": str(), "action": {Type: "string", Enum: []string{"issue", "revoke"}},
		"approver": str(), "approvals": {Type: "integer"},
	}, "resource", "action", "approver", "approvals")
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

	list := func(item string) *Schema {
		return object(map[string]*Schema{
			"items":       {Type: "array", Items: ref(item)},
			"next_cursor": str(),
		}, "items")
	}

	problemSchema := object(map[string]*Schema{
		"type": str(), "title": str(), "status": {Type: "integer"}, "detail": str(), "instance": str(),
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
	fipsStatus := object(map[string]*Schema{
		"module_active":    {Type: "boolean"},
		"required":         {Type: "boolean"},
		"self_test_passed": {Type: "boolean"},
	}, "module_active", "required", "self_test_passed")
	editionsInfo := object(map[string]*Schema{
		"tier":         {Type: "string", Enum: editionTiers},
		"state":        {Type: "string", Enum: editionStates},
		"customer":     str(),
		"license_id":   str(),
		"expires_at":   timestamp(),
		"read_only_at": timestamp(),
		"tenant_band":  {Type: "integer"},
		"features":     {Type: "array", Items: ref("EditionFeature")},
		"fips":         ref("FIPSStatus"),
	}, "tier", "state", "features", "fips")
	managedOfferingStatus := object(map[string]*Schema{
		"served":               {Type: "boolean"},
		"deployment_model":     str(),
		"tier":                 {Type: "string", Enum: editionTiers},
		"license_state":        {Type: "string", Enum: editionStates},
		"provider_plane_mode":  {Type: "string", Enum: featureModes},
		"tenant_band":          {Type: "integer"},
		"idempotency_required": {Type: "boolean"},
		"event_type":           str(),
		"mutation_path":        str(),
	}, "served", "deployment_model", "tier", "license_state", "provider_plane_mode", "idempotency_required", "event_type", "mutation_path")
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

	certificate := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "owner_id": uuid(), "subject": str(),
		"sans": {Type: "array", Items: str()}, "issuer": str(), "serial": str(),
		"fingerprint": str(), "key_algorithm": str(), "not_before": timestamp(), "not_after": timestamp(),
		"deployment_location": str(), "source": str(), "created_at": timestamp(),
		"status":            {Type: "string", Enum: []string{"active", "superseded", "revoked"}},
		"revoked_at":        timestamp(),
		"revocation_reason": str(),
	}, "id", "tenant_id", "subject", "fingerprint", "status")
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
		"external_source_count": {Type: "integer"},
		"imported_count":        {Type: "integer"},
		"discovered_count":      {Type: "integer"},
		"unknown_expiry_count":  {Type: "integer"},
		"health":                {Type: "string", Enum: []string{"ok", "warning", "critical"}},
	}, "total", "active", "revoked", "superseded", "expired", "expiring_7d", "expiring_30d", "expiring_90d", "external_source_count", "imported_count", "discovered_count", "unknown_expiry_count", "health")
	certificateExpiryBucket := object(map[string]*Schema{
		"name":  {Type: "string", Enum: []string{"expired", "expiring_7d", "expiring_30d", "expiring_90d", "later", "unknown"}},
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

	discoverySourceKinds := []string{"network", "ssh", "cloud_certificate", "cloud_secret", "ct_log", "drift", "secret_store", "api_key", "agent", "manual", "nhi_cross_surface", "oauth_grant", "service_account", "nhi_behavior", "credential_compromise", "k8s_ingress_gateway"}
	discoverySource := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "kind": {Type: "string", Enum: discoverySourceKinds},
		"name": str(), "config": {Type: "object"}, "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "kind", "name", "config", "created_at", "updated_at")
	discoverySourceReq := object(map[string]*Schema{
		"kind": {Type: "string", Enum: discoverySourceKinds}, "name": str(), "config": {Type: "object"},
	}, "kind", "name")
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
		"status":  {Type: "string", Enum: []string{"queued", "running", "succeeded", "partial", "failed"}},
		"dry_run": {Type: "boolean"}, "requested_by": str(),
		"targets": {Type: "integer"}, "discovered": {Type: "integer"}, "failed": {Type: "integer"},
		"rejected": {Type: "integer"}, "error": str(), "started_at": timestamp(),
		"completed_at": timestamp(), "created_at": timestamp(),
	}, "id", "tenant_id", "source_id", "status", "dry_run", "targets", "discovered", "failed", "rejected", "created_at")
	discoveryRunReq := object(map[string]*Schema{
		"source_id": uuid(), "schedule_id": uuid(), "dry_run": {Type: "boolean"},
	}, "source_id")
	discoveryFinding := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "run_id": uuid(), "source_id": uuid(),
		"kind": str(), "ref": str(), "provenance": str(), "fingerprint": str(),
		"risk_score": {Type: "integer"}, "metadata": {Type: "object"}, "discovered_at": timestamp(),
		"triage_status":       {Type: "string", Enum: []string{"unmanaged", "investigating", "managed", "dismissed"}},
		"managed_identity_id": uuid(), "triage_actor": str(), "triage_reason": str(), "triaged_at": timestamp(),
	}, "id", "tenant_id", "run_id", "source_id", "kind", "ref", "provenance", "fingerprint", "metadata", "discovered_at")
	discoveryFindingTriageReq := object(map[string]*Schema{
		"managed_identity_id": uuid(), "reason": str(),
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
	connectorCatalogItem := object(map[string]*Schema{
		"name": str(), "kind": str(), "delivery_mode": str(), "rollback": str(),
	}, "name", "kind", "delivery_mode", "rollback")
	connectorCatalog := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ConnectorCatalogItem")},
	}, "items")
	acmeDNS01ProviderCatalogItem := object(map[string]*Schema{
		"name":                        str(),
		"display_name":                str(),
		"kind":                        str(),
		"served":                      {Type: "boolean"},
		"propagation_preflight":       {Type: "boolean"},
		"conformance":                 str(),
		"credential_reference_fields": {Type: "array", Items: str()},
		"secret_fields":               {Type: "array", Items: str()},
		"capabilities":                {Type: "array", Items: str()},
		"provider_package":            str(),
		"notes":                       str(),
	}, "name", "display_name", "kind", "served", "propagation_preflight", "conformance", "credential_reference_fields", "secret_fields", "capabilities", "provider_package")
	acmeDNS01ProviderCatalog := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ACMEDNS01ProviderCatalogItem")},
	}, "items")
	deploymentTargetReq := object(map[string]*Schema{
		"name": str(), "connector": str(), "config": {Type: "object"},
	}, "name", "connector")
	deploymentTarget := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "name": str(), "connector": str(), "config": {Type: "object"}, "created_at": timestamp(),
	}, "id", "tenant_id", "name", "connector", "config", "created_at")
	identityConnectorTargetReq := object(map[string]*Schema{
		"target_id": uuid(),
	}, "target_id")
	connectorTargetActionReq := object(map[string]*Schema{
		"identity_id": uuid(), "reason": str(),
	}, "identity_id")
	connectorDelivery := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "outbox_id": {Type: "integer"}, "identity_id": uuid(),
		"destination": str(), "connector": str(), "target": str(), "fingerprint": str(),
		"status":   {Type: "string", Enum: []string{"unrouted", "delivered", "failed", "test_succeeded", "rollback_recorded"}},
		"attempts": {Type: "integer"}, "reason": str(), "detail": str(), "rollback_ref": str(),
		"idempotency_key": str(), "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "destination", "connector", "target", "status", "attempts", "created_at", "updated_at")
	notification := object(map[string]*Schema{
		"id": str(), "tenant_id": uuid(), "destination": str(), "kind": str(),
		"certificate_id": str(), "subject": str(), "serial": str(), "not_after": timestamp(),
		"detail": str(), "severity": {Type: "string", Enum: []string{"low", "informational", "warning", "critical"}},
		"routing_policy_id": str(), "threshold_days": {Type: "integer"},
		"status":   {Type: "string", Enum: []string{"pending", "sent", "dead", "read"}},
		"attempts": {Type: "integer"}, "last_error": str(), "idempotency_key": str(),
		"created_at": timestamp(), "delivered_at": timestamp(), "read_at": timestamp(),
	}, "id", "tenant_id", "destination", "status", "attempts", "created_at")
	outboxCircuit := object(map[string]*Schema{
		"tenant_id": uuid(), "destination": str(),
		"state":      {Type: "string", Enum: []string{"closed", "open", "half-open"}},
		"failures":   {Type: "integer"},
		"open_until": timestamp(), "updated_at": timestamp(), "last_error": str(),
	}, "tenant_id", "destination", "state", "failures", "updated_at")
	rotationRun := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "identity_id": uuid(), "outbox_id": {Type: "integer"},
		"status":  {Type: "string", Enum: []string{"running", "succeeded", "failed"}},
		"trigger": str(), "reason": str(), "predecessor_fingerprint": str(),
		"successor_fingerprint": str(), "rollback_ref": str(), "error": str(),
		"idempotency_key": str(), "created_at": timestamp(), "updated_at": timestamp(),
		"completed_at": timestamp(),
	}, "id", "tenant_id", "identity_id", "status", "trigger", "created_at", "updated_at")
	incidentExecutionReq := object(map[string]*Schema{
		"identity_id": uuid(), "reason": str(), "replacement_name": str(),
		"connector": str(), "target": str(), "delivery_rollback_ref": str(),
	}, "identity_id")
	fleetHealthGate := object(map[string]*Schema{
		"name": str(), "status": str(),
	}, "name", "status")
	fleetBatch := object(map[string]*Schema{
		"index": {Type: "integer"}, "status": str(),
		"identity_ids":             {Type: "array", Items: uuid()},
		"replacement_identity_ids": {Type: "array", Items: uuid()},
		"health_gate":              str(),
	}, "index", "status", "identity_ids", "replacement_identity_ids")
	fleetReissuanceReq := object(map[string]*Schema{
		"issuer_id": uuid(), "reason": str(), "batch_size": {Type: "integer"},
		"connector": str(), "target": str(), "rollback_ref": str(),
		"health_gates":  {Type: "array", Items: ref("FleetReissuanceHealthGate")},
		"evidence_hint": str(),
	}, "issuer_id")
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
	}, "subject", "scopes", "ttl_seconds")
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
	auditBundle := object(map[string]*Schema{
		"format": str(),
		"bundle": str(), // a compact JWS whose payload is the signed evidence bundle
	}, "format", "bundle")
	complianceEvidencePack := object(map[string]*Schema{
		"format":         str(),
		"framework":      {Type: "string", Enum: []string{"pci-dss", "hipaa", "soc2", "fedramp", "cnsa-2.0", "fips-140", "common-criteria", "cabf-br", "webtrust", "etsi"}},
		"signed_export":  {Type: "object"},
		"public_key_der": {Type: "string", Format: "byte"},
	}, "format", "framework", "signed_export", "public_key_der")
	privacyErasureReq := object(map[string]*Schema{
		"subject": str(),
		"reason":  str(),
	}, "subject")
	privacyErasureSelectors := object(map[string]*Schema{
		"owner_ids":                {Type: "array", Items: uuid()},
		"identity_ids":             {Type: "array", Items: uuid()},
		"certificate_fingerprints": {Type: "array", Items: str()},
		"ssh_key_ids":              {Type: "array", Items: uuid()},
		"attestation_ids":          {Type: "array", Items: uuid()},
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
	attestedSVID := object(map[string]*Schema{
		"certificate_pem": str(),
		"credential_id":   str(),
		"subject":         str(),
		"not_after":       timestamp(),
		"attestation":     ref("Attestation"),
	}, "certificate_pem", "credential_id", "subject", "not_after", "attestation")
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
	sshAttestedUserCertReq := object(map[string]*Schema{
		"method":         {Type: "string", Enum: []string{"aws_iid", "azure_imds", "gcp_iit", "github_oidc", "k8s_sat", "tpm"}},
		"payload_base64": str(),
		"public_key":     str(),
		"key_id":         str(),
		"ttl_seconds":    {Type: "integer"},
	}, "method", "payload_base64", "public_key")
	sshAttestedUserCert := object(map[string]*Schema{
		"certificate":  str(),
		"serial":       {Type: "integer"},
		"key_id":       str(),
		"subject":      str(),
		"principals":   {Type: "array", Items: str()},
		"valid_before": timestamp(),
		"attestation":  ref("Attestation"),
	}, "certificate", "serial", "key_id", "subject", "principals", "valid_before", "attestation")
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
	}, "agent_id", "method", "payload_base64", "public_key_pem", "scopes")
	brokerAgentIdentity := object(map[string]*Schema{
		"agent_id":        str(),
		"node_id":         str(),
		"subject":         str(),
		"credential_id":   str(),
		"certificate_id":  uuid(),
		"certificate_pem": str(),
		"scopes":          {Type: "array", Items: str()},
		"not_after":       timestamp(),
		"attestation":     ref("Attestation"),
	}, "agent_id", "node_id", "subject", "credential_id", "certificate_id", "certificate_pem", "scopes", "not_after", "attestation")
	ephemeralCredentialReq := object(map[string]*Schema{
		"request_id":     str(),
		"method":         str(),
		"payload_base64": str(),
		"public_key_pem": str(),
		"ttl_seconds":    {Type: "integer"},
	}, "request_id", "method", "payload_base64", "public_key_pem")
	ephemeralCredential := object(map[string]*Schema{
		"state":              {Type: "string", Enum: []string{EphemeralStateAwaitingApproval, EphemeralStateIssued}},
		"request_id":         str(),
		"subject":            str(),
		"credential_id":      str(),
		"certificate_id":     uuid(),
		"certificate_pem":    str(),
		"required_approvals": {Type: "integer"},
		"approvals":          {Type: "integer"},
		"expires_at":         timestamp(),
		"not_after":          timestamp(),
		"attestation":        ref("Attestation"),
	}, "state", "request_id", "subject", "required_approvals", "approvals", "expires_at", "attestation")
	ephemeralApprovalReq := object(map[string]*Schema{
		"action": {Type: "string", Enum: []string{"issue"}},
	}, "action")
	ephemeralApproval := object(map[string]*Schema{
		"resource": str(), "action": str(), "approver": str(), "approvals": {Type: "integer"},
	}, "resource", "action", "approver", "approvals")
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
		"from": str(), "to": str(), "type": str(),
	}, "from", "to", "type")
	graphResponse := object(map[string]*Schema{
		"nodes": {Type: "array", Items: ref("GraphNode")},
		"edges": {Type: "array", Items: ref("GraphEdge")},
	}, "nodes", "edges")
	graphReachable := object(map[string]*Schema{
		"from":  str(),
		"nodes": {Type: "array", Items: ref("GraphNode")},
	}, "from", "nodes")
	graphImpact := object(map[string]*Schema{
		"node":     ref("GraphNode"),
		"affected": {Type: "array", Items: ref("GraphNode")},
		"by_kind":  {Type: "object"},
	}, "node", "affected", "by_kind")
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
		"status": str(), "phase": str(), "reason": str(), "batch_size": {Type: "integer"},
		"batch_count": {Type: "integer"}, "connector": str(), "target": str(),
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
	}, "id", "tenant_id", "issuer_id", "status", "phase", "batch_size", "batch_count", "graph_impact", "affected_identity_ids", "replacement_identity_ids", "revoked_identity_ids", "batches", "health_gates", "rollback_refs", "created_at", "updated_at")
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

	agentDiscoveryCapability := object(map[string]*Schema{
		"source_kind":       str(),
		"label":             str(),
		"reported_over":     str(),
		"metadata_only":     {Type: "boolean"},
		"private_key_bytes": {Type: "boolean"},
	}, "source_kind", "label", "reported_over", "metadata_only", "private_key_bytes")
	agent := object(map[string]*Schema{
		"id": uuid(), "name": str(), "status": str(), "version": str(), "last_seen_at": timestamp(),
		"inventory_report_path":  str(),
		"discovery_capabilities": {Type: "array", Items: ref("AgentDiscoveryCapability")},
	}, "id", "name", "status", "inventory_report_path", "discovery_capabilities")
	agentList := object(map[string]*Schema{
		"agents":      {Type: "array", Items: ref("Agent")},
		"next_cursor": str(),
	}, "agents")
	enrollmentToken := object(map[string]*Schema{
		"token": str(), "enroll_path": str(),
	}, "token")
	agentCertRevocationReq := object(map[string]*Schema{
		"agent": str(), "serial": str(), "fingerprint": str(), "reason": str(),
	})
	agentCertRevocation := object(map[string]*Schema{
		"agent_id": uuid(), "agent": str(), "serial": str(), "fingerprint": str(),
		"reason": str(), "revoked_at": timestamp(),
	}, "agent_id", "revoked_at")
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
	cbomScanReq := object(map[string]*Schema{
		"tls_endpoints": {Type: "array", Items: str()},
		"host_configs":  {Type: "array", Items: str()},
	})
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
	pqcMigrationReq := object(map[string]*Schema{
		"asset_ids":           {Type: "array", Items: uuid()},
		"target_algorithm":    str(),
		"protocol":            str(),
		"rollback_on_failure": {Type: "boolean"},
	}, "asset_ids", "target_algorithm")
	pqcMigration := object(map[string]*Schema{
		"run_id":              uuid(),
		"queued":              {Type: "integer"},
		"target_algorithm":    str(),
		"effective_algorithm": str(),
		"protocol":            str(),
		"rollback_configured": {Type: "boolean"},
		"migration_progress":  ref("CBOMMigrationProgress"),
		"queued_at":           timestamp(),
	}, "run_id", "queued", "target_algorithm", "effective_algorithm", "protocol", "rollback_configured", "migration_progress", "queued_at")
	pqcRollbackReq := object(map[string]*Schema{
		"asset_ids": {Type: "array", Items: uuid()},
		"reason":    str(),
	}, "asset_ids")
	pqcRollback := object(map[string]*Schema{
		"run_id":             uuid(),
		"queued":             {Type: "integer"},
		"reason":             str(),
		"migration_progress": ref("CBOMMigrationProgress"),
		"queued_at":          timestamp(),
	}, "run_id", "queued", "reason", "migration_progress", "queued_at")

	profile := object(map[string]*Schema{
		"id": uuid(), "name": str(), "version": {Type: "integer"},
		"active": {Type: "boolean"}, "created_by": str(), "spec": {Type: "object"},
	}, "id", "name", "version")
	profileReq := object(map[string]*Schema{
		"name": str(), "spec": {Type: "object"},
	}, "name", "spec")

	// Served secrets/identity surface (GAP-006). The metadata view never carries a
	// value; the value/share/key views are the only places a secret leaves the
	// boundary, returned solely to the authorized caller (AN-8).
	secretReq := object(map[string]*Schema{
		"name": str(), "value": str(),
	}, "name", "value")
	secretImportReq := object(map[string]*Schema{
		"prefix": str(), "values": {Type: "object"},
	}, "values")
	secretMeta := object(map[string]*Schema{
		"name": str(), "version": {Type: "integer"}, "created_at": timestamp(), "updated_at": timestamp(),
	}, "name", "version")
	dynamicLeaseReq := object(map[string]*Schema{
		"provider": str(), "role": str(), "ttl_seconds": {Type: "integer"},
	}, "provider", "role", "ttl_seconds")
	secretRotationReq := object(map[string]*Schema{
		"provider": str(), "key": str(), "old_ref": str(),
	}, "provider", "key", "old_ref")
	secretRotation := object(map[string]*Schema{
		"key": str(), "old_ref": str(), "new_ref": str(),
		"completed": {Type: "boolean"}, "rolled_back": {Type: "boolean"},
		"rollback_attempted": {Type: "boolean"}, "rollback_failed": {Type: "boolean"},
		"rollback_error": str(), "failed_phase": str(), "error": str(),
	}, "key", "old_ref", "new_ref", "completed", "rolled_back", "rollback_attempted", "rollback_failed")
	secretSyncReq := object(map[string]*Schema{
		"name": str(), "target": str(), "remote_key": str(),
	}, "name", "target")
	secretSync := object(map[string]*Schema{
		"name": str(), "target": str(), "remote_key": str(),
		"enqueued": {Type: "boolean"}, "delivered": {Type: "boolean"},
	}, "name", "target", "remote_key", "enqueued", "delivered")
	secretScanReq := object(map[string]*Schema{
		"path": str(),
	}, "path")
	secretScanFinding := object(map[string]*Schema{
		"rule_id": str(), "file": str(), "line": {Type: "integer"}, "credential_ref": str(),
	}, "rule_id", "file", "line", "credential_ref")
	secretScan := object(map[string]*Schema{
		"run_id": uuid(), "scanner": str(), "engine_version": str(),
		"rules_active": {Type: "integer"}, "findings_count": {Type: "integer"},
		"findings": {Type: "array", Items: ref("SecretScanFinding")},
	}, "run_id", "scanner", "engine_version", "rules_active", "findings_count", "findings")
	dynamicLeaseRenewReq := object(map[string]*Schema{
		"extend_seconds": {Type: "integer"},
	}, "extend_seconds")
	dynamicLease := object(map[string]*Schema{
		"id": str(), "provider": str(), "role": str(), "state": str(),
		"credential": str(), "issued_at": timestamp(), "expires_at": timestamp(),
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
		"key_id": str(), "artifact_type": str(), "digest": {Type: "string", Format: "byte"},
	}, "key_id", "artifact_type", "digest")
	codeSigningKeylessReq := object(map[string]*Schema{
		"artifact_type": str(), "digest": {Type: "string", Format: "byte"},
		"identity_method": str(), "identity_payload": {Type: "string", Format: "byte"},
		"fulcio_san": str(), "fulcio_issuer": str(),
	}, "artifact_type", "digest", "identity_method", "identity_payload")
	codeSigningSignature := object(map[string]*Schema{
		"algorithm": str(), "key_id": str(), "artifact_type": str(),
		"signature": {Type: "string", Format: "byte"}, "public_key_der": {Type: "string", Format: "byte"},
		"fulcio_san": str(), "fulcio_issuer": str(), "transparency_destination": str(),
	}, "algorithm", "artifact_type", "signature", "public_key_der")
	// Managed-key (BYOK/HSM) lifecycle schemas (CRYPTO-005). public_der is the PKIX
	// public key (base64 in JSON); the private material is never represented here.
	managedKeyGenerateReq := object(map[string]*Schema{
		"algorithm": str(),
	}, "algorithm")
	managedKeyActionReq := object(map[string]*Schema{
		"key_id": str(),
	}, "key_id")
	managedKey := object(map[string]*Schema{
		"key_id": str(), "algorithm": str(), "version": {Type: "integer"}, "state": str(),
		"public_der": {Type: "string", Format: "byte"},
	}, "key_id", "algorithm", "version", "state")
	secretValue := object(map[string]*Schema{
		"name": str(), "value": str(), "version": {Type: "integer"},
	}, "name", "value")
	shareReq := object(map[string]*Schema{
		"value": str(), "ttl_seconds": {Type: "integer"},
	}, "value")
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
		"common_name": str(), "ttl_seconds": {Type: "integer"},
	}, "common_name")
	pkiSecret := object(map[string]*Schema{
		"serial": str(), "common_name": str(), "certificate": str(), "private_key": str(),
	}, "serial", "certificate", "private_key")
	machineLoginReq := object(map[string]*Schema{
		"method": str(), "credential": str(),
	}, "credential")
	machineLoginResp := object(map[string]*Schema{
		"session_id": str(),
		"principal":  str(),
		"method":     str(),
		"scopes":     {Type: "array", Items: str()},
		"expires_at": timestamp(),
	}, "session_id", "principal", "method", "scopes", "expires_at")

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
		"redaction":             str(),
		"residual_refusal_gate": {Type: "boolean"},
		"mcp_identity":          str(),
		"mcp_write_tools":       {Type: "boolean"},
		"rate_max":              {Type: "integer"},
		"rate_window_seconds":   {Type: "integer"},
	}, "enabled", "model_configured", "model_mode", "egress", "redaction", "residual_refusal_gate")
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
		"Problem":                               problemSchema,
		"EnterpriseSupportStatus":               enterpriseSupportStatus,
		"EnterpriseSupportTier":                 enterpriseSupportTier,
		"EnterpriseSupportSLATarget":            enterpriseSupportSLATarget,
		"EnterpriseProfessionalService":         enterpriseProfessionalService,
		"ManagedOfferingStatus":                 managedOfferingStatus,
		"ManagedTenantProvisionRequest":         managedTenantReq,
		"ManagedTenant":                         managedTenant,
		"NHIReviewItemRequest":                  nhiReviewItemReq,
		"NHIReviewCampaignStartRequest":         nhiReviewCampaignStartReq,
		"NHIReviewDecisionRequest":              nhiReviewDecisionReq,
		"NHIReviewItem":                         nhiReviewItem,
		"NHIReviewCampaign":                     nhiReviewCampaign,
		"NHIReviewCampaignList":                 list("NHIReviewCampaign"),
		"AgentDiscoveryCapability":              agentDiscoveryCapability,
		"Agent":                                 agent,
		"AgentList":                             agentList,
		"EnrollmentToken":                       enrollmentToken,
		"AgentCertRevocationRequest":            agentCertRevocationReq,
		"AgentCertRevocation":                   agentCertRevocation,
		"RiskComponents":                        riskComponents,
		"CredentialRisk":                        credentialRisk,
		"CredentialRiskList":                    credentialRiskList,
		"CBOMScanRequest":                       cbomScanReq,
		"CBOMReport":                            cbomReport,
		"CBOMMigrationProgress":                 cbomMigrationProgress,
		"CBOMAsset":                             cbomAsset,
		"CBOMInventory":                         cbomInventory,
		"CBOMScan":                              cbomScan,
		"PQCMigrationRequest":                   pqcMigrationReq,
		"PQCMigration":                          pqcMigration,
		"PQCMigrationRollbackRequest":           pqcRollbackReq,
		"PQCMigrationRollback":                  pqcRollback,
		"Certificate":                           certificate,
		"CertificateIngest":                     certificateIngest,
		"CertificateList":                       list("Certificate"),
		"CertificateHealthSummary":              certificateHealthSummary,
		"CertificateExpiryBucket":               certificateExpiryBucket,
		"CertificateSourceHealth":               certificateSourceHealth,
		"CertificateHealthItem":                 certificateHealthItem,
		"CertificateHealthDashboard":            certificateHealthDashboard,
		"DiscoverySource":                       discoverySource,
		"DiscoverySourceRequest":                discoverySourceReq,
		"DiscoverySourceList":                   list("DiscoverySource"),
		"DiscoverySchedule":                     discoverySchedule,
		"DiscoveryScheduleRequest":              discoveryScheduleReq,
		"DiscoveryScheduleList":                 list("DiscoverySchedule"),
		"DiscoveryRun":                          discoveryRun,
		"DiscoveryRunRequest":                   discoveryRunReq,
		"DiscoveryRunList":                      list("DiscoveryRun"),
		"DiscoveryFinding":                      discoveryFinding,
		"DiscoveryFindingTriageRequest":         discoveryFindingTriageReq,
		"DiscoveryFindingList":                  list("DiscoveryFinding"),
		"DiscoveryMonitoringSummary":            discoveryMonitoringSummary,
		"DiscoveryMonitoringSource":             discoveryMonitoringSource,
		"DiscoveryMonitoring":                   discoveryMonitoring,
		"ACMEDNS01ProviderCatalogItem":          acmeDNS01ProviderCatalogItem,
		"ACMEDNS01ProviderCatalog":              acmeDNS01ProviderCatalog,
		"ConnectorCatalogItem":                  connectorCatalogItem,
		"ConnectorCatalog":                      connectorCatalog,
		"DeploymentTargetRequest":               deploymentTargetReq,
		"DeploymentTarget":                      deploymentTarget,
		"DeploymentTargetList":                  list("DeploymentTarget"),
		"IdentityConnectorTargetRequest":        identityConnectorTargetReq,
		"ConnectorTargetActionRequest":          connectorTargetActionReq,
		"ConnectorDelivery":                     connectorDelivery,
		"ConnectorDeliveryList":                 list("ConnectorDelivery"),
		"Notification":                          notification,
		"NotificationList":                      list("Notification"),
		"OutboxCircuit":                         outboxCircuit,
		"OutboxCircuitList":                     list("OutboxCircuit"),
		"RotationRun":                           rotationRun,
		"RotationRunList":                       list("RotationRun"),
		"IncidentExecutionRequest":              incidentExecutionReq,
		"IncidentExecution":                     incidentExecution,
		"IncidentExecutionList":                 list("IncidentExecution"),
		"FleetReissuanceHealthGate":             fleetHealthGate,
		"FleetReissuanceBatch":                  fleetBatch,
		"FleetReissuanceRequest":                fleetReissuanceReq,
		"FleetReissuanceActionRequest":          fleetReissuanceActionReq,
		"FleetReissuanceRun":                    fleetReissuanceRun,
		"FleetReissuanceRunList":                list("FleetReissuanceRun"),
		"FleetReissuanceEvidence":               fleetReissuanceEvidence,
		"ServiceNowTicketRequest":               serviceNowTicketReq,
		"ITSMTicket":                            itsmTicket,
		"Role":                                  role,
		"RoleList":                              list("Role"),
		"OIDCTenantMapping":                     oidcTenantMapping,
		"OIDCMappingStatus":                     oidcMappingStatus,
		"Member":                                member,
		"MemberRequest":                         memberReq,
		"MemberList":                            list("Member"),
		"OffboardMemberRequest":                 offboardMemberReq,
		"OffboardMemberResponse":                offboardMemberResp,
		"APIToken":                              apiToken,
		"APITokenList":                          list("APIToken"),
		"APITokenCreateRequest":                 apiTokenCreateReq,
		"APITokenCreateResponse":                apiTokenCreateResp,
		"APITokenRevokeRequest":                 apiTokenRevokeReq,
		"AuditEvent":                            auditEvent,
		"AuditEventList":                        auditEventList,
		"AuditBundle":                           auditBundle,
		"ComplianceEvidencePack":                complianceEvidencePack,
		"PrivacySubjectErasureRequest":          privacyErasureReq,
		"PrivacyErasureSelectors":               privacyErasureSelectors,
		"PrivacySubjectErasure":                 privacySubjectErasure,
		"PrivacySubjectErasureList":             list("PrivacySubjectErasure"),
		"PrivacyRetentionCutoffs":               privacyRetentionCutoffs,
		"PrivacyRetentionRun":                   privacyRetentionRun,
		"PrivacyRetentionRunList":               list("PrivacyRetentionRun"),
		"PrivacyCatalogEntry":                   privacyCatalogEntry,
		"PrivacyCatalog":                        privacyCatalog,
		"PrivacySubjectExportRequest":           privacySubjectExportReq,
		"PrivacySubjectExport":                  privacySubjectExport,
		"Attestation":                           attestation,
		"AttestedSVIDRequest":                   attestedSVIDReq,
		"AttestedSVID":                          attestedSVID,
		"SSHStatus":                             sshStatus,
		"SSHTrustRolloutRequest":                sshTrustRolloutReq,
		"SSHTrustRollout":                       sshTrustRollout,
		"SSHAttestedUserCertRequest":            sshAttestedUserCertReq,
		"SSHAttestedUserCert":                   sshAttestedUserCert,
		"SSHRevokeCertificateRequest":           sshRevokeCertReq,
		"SSHHostRetireRequest":                  sshHostRetireReq,
		"SSHHostRetirement":                     sshHostRetirement,
		"BrokerAgentIdentityRequest":            brokerAgentIdentityReq,
		"BrokerAgentIdentity":                   brokerAgentIdentity,
		"EphemeralCredentialRequest":            ephemeralCredentialReq,
		"EphemeralCredential":                   ephemeralCredential,
		"EphemeralAPIKeyRequest":                ephemeralAPIKeyReq,
		"EphemeralAPIKey":                       ephemeralAPIKey,
		"EphemeralApprovalRequest":              ephemeralApprovalReq,
		"EphemeralApproval":                     ephemeralApproval,
		"PAMSessionRequest":                     pamSessionReq,
		"PAMSession":                            pamSession,
		"PAMSessionList":                        list("PAMSession"),
		"PAMPostgresCredential":                 pamPostgresCredential,
		"PAMSSHCredential":                      pamSSHCredential,
		"GraphNode":                             graphNode,
		"GraphEdge":                             graphEdge,
		"GraphResponse":                         graphResponse,
		"GraphReachable":                        graphReachable,
		"GraphImpact":                           graphImpact,
		"GraphQueryResult":                      graphQueryResult,
		"Owner":                                 owner,
		"OwnerRequest":                          ownerReq,
		"OwnerList":                             list("Owner"),
		"Profile":                               profile,
		"ProfileRequest":                        profileReq,
		"ProfileList":                           list("Profile"),
		"Issuer":                                issuer,
		"IssuerRequest":                         issuerReq,
		"IssuerList":                            list("Issuer"),
		"CASpec":                                caSpec,
		"CACeremonyStartRequest":                caCeremonyStartReq,
		"CAKeyCeremony":                         caCeremony,
		"CACreateRootRequest":                   caCreateRootReq,
		"CAImportOfflineRootRequest":            caImportOfflineRootReq,
		"CAImportExistingRequest":               caImportExistingReq,
		"CACreateIntermediateRequest":           caCreateIntermediateReq,
		"CACreateOfflineIntermediateCSRRequest": caCreateOfflineIntermediateCSRReq,
		"CAImportOfflineIntermediateRequest":    caImportOfflineIntermediateReq,
		"CAIntermediateCSR":                     caIntermediateCSR,
		"CAIssueIntermediateRequest":            caIssueIntermediateReq,
		"CAAuthority":                           caAuthority,
		"CAAuthorityList":                       list("CAAuthority"),
		"CADiscoveryItem":                       caDiscoveryItem,
		"CADiscoverySummary":                    caDiscoverySummary,
		"CADiscoveryInventory":                  caDiscoveryInventory,
		"CAIssueLeafRequest":                    caIssueLeafReq,
		"CAIssuedIntermediate":                  caIssuedIntermediate,
		"CAIssuedLeaf":                          caIssuedLeaf,
		"ExternalCA":                            externalCA,
		"ExternalCAList":                        list("ExternalCA"),
		"ExternalCAIssueRequest":                externalCAIssueReq,
		"ExternalCAIssuedCertificate":           externalCAIssued,
		"Identity":                              identity,
		"IdentityRequest":                       identityReq,
		"IdentityList":                          list("Identity"),
		"TransitionRequest":                     transitionReq,
		"BulkRevokeRequest":                     bulkRevokeReq,
		"BulkRevokeItem":                        bulkRevokeItem,
		"BulkRevokeResult":                      bulkRevokeResult,
		"ApprovalRequest":                       approvalReq,
		"Approval":                              approval,
		"BreakglassBundle":                      breakglassBundle,
		"BreakglassReconcileRequest":            breakglassReconcileReq,
		"BreakglassReconcileResponse":           breakglassReconcileResp,
		"SecretRequest":                         secretReq,
		"SecretImportRequest":                   secretImportReq,
		"SecretRecoverRequest":                  secretRecoverReq,
		"SecretMeta":                            secretMeta,
		"SecretMetaList":                        list("SecretMeta"),
		"SecretValue":                           secretValue,
		"SecretRotationRequest":                 secretRotationReq,
		"SecretRotation":                        secretRotation,
		"SecretSyncRequest":                     secretSyncReq,
		"SecretSync":                            secretSync,
		"SecretScanRequest":                     secretScanReq,
		"SecretScanFinding":                     secretScanFinding,
		"SecretScan":                            secretScan,
		"DynamicLeaseRequest":                   dynamicLeaseReq,
		"DynamicLeaseRenewRequest":              dynamicLeaseRenewReq,
		"DynamicLease":                          dynamicLease,
		"TransitKeyRequest":                     transitKeyReq,
		"TransitRotateRequest":                  transitRotateReq,
		"TransitKey":                            transitKey,
		"TransitEncryptRequest":                 transitEncryptReq,
		"TransitDecryptRequest":                 transitCiphertextReq,
		"TransitRewrapRequest":                  transitCiphertextReq,
		"TransitCiphertext":                     transitCiphertext,
		"TransitPlaintext":                      transitPlaintext,
		"TransitHMACRequest":                    transitHMACReq,
		"TransitHMAC":                           transitHMAC,
		"TransitSignRequest":                    transitSignReq,
		"TransitSignature":                      transitSignature,
		"TransitVerifyRequest":                  transitVerifyReq,
		"TransitVerify":                         transitVerify,
		"CodeSigningRequest":                    codeSigningReq,
		"CodeSigningKeylessRequest":             codeSigningKeylessReq,
		"CodeSigningSignature":                  codeSigningSignature,
		"ManagedKeyGenerateRequest":             managedKeyGenerateReq,
		"ManagedKeyActionRequest":               managedKeyActionReq,
		"ManagedKey":                            managedKey,
		"ShareRequest":                          shareReq,
		"ShareToken":                            shareToken,
		"ShareRedeemRequest":                    shareRedeemReq,
		"ShareValue":                            shareValue,
		"PKISecretRequest":                      pkiSecretReq,
		"PKISecret":                             pkiSecret,
		"MachineLoginRequest":                   machineLoginReq,
		"MachineLoginResponse":                  machineLoginResp,
		"AIQueryRequest":                        aiQueryReq,
		"RCARequest":                            rcaReq,
		"AIAnswer":                              aiAnswer,
		"AIStatus":                              aiStatus,
		"MCPToolList":                           mcpToolList,
		"MCPToolCall":                           mcpToolCall,
		"MCPToolResult":                         mcpToolResult,
		"EditionFeature":                        editionFeature,
		"FIPSStatus":                            fipsStatus,
		"EditionsInfo":                          editionsInfo,
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
