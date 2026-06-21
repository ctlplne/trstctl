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
	OperationID      string                `json:"operationId"`
	Summary          string                `json:"summary,omitempty"`
	Parameters       []Parameter           `json:"parameters,omitempty"`
	RequestBody      *RequestBody          `json:"requestBody,omitempty"`
	Responses        map[string]Response   `json:"responses"`
	Security         []map[string][]string `json:"security,omitempty"`
	XPermission      string                `json:"x-trstctl-permission,omitempty"`
	XPublicRationale string                `json:"x-trstctl-public-rationale,omitempty"`
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
					Description: "Verified OIDC browser session; mutating requests also require the double-submit CSRF token.",
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

	approvalReq := object(map[string]*Schema{
		"action": {Type: "string", Enum: []string{"issue", "revoke"}},
	}, "action")
	approval := object(map[string]*Schema{
		"resource": str(), "action": {Type: "string", Enum: []string{"issue", "revoke"}},
		"approver": str(), "approvals": {Type: "integer"},
	}, "resource", "action", "approver", "approvals")

	list := func(item string) *Schema {
		return object(map[string]*Schema{
			"items":       {Type: "array", Items: ref(item)},
			"next_cursor": str(),
		}, "items")
	}

	problemSchema := object(map[string]*Schema{
		"type": str(), "title": str(), "status": {Type: "integer"}, "detail": str(), "instance": str(),
	})

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

	discoverySourceKinds := []string{"network", "ssh", "cloud_certificate", "secret_store", "api_key", "agent", "manual"}
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
	}, "id", "tenant_id", "run_id", "source_id", "kind", "ref", "provenance", "fingerprint", "metadata", "discovered_at")
	connectorCatalogItem := object(map[string]*Schema{
		"name": str(), "kind": str(), "delivery_mode": str(), "rollback": str(),
	}, "name", "kind", "delivery_mode", "rollback")
	connectorCatalog := object(map[string]*Schema{
		"items": {Type: "array", Items: ref("ConnectorCatalogItem")},
	}, "items")
	connectorDelivery := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "outbox_id": {Type: "integer"}, "identity_id": uuid(),
		"destination": str(), "connector": str(), "target": str(), "fingerprint": str(),
		"status":   {Type: "string", Enum: []string{"unrouted", "delivered", "failed"}},
		"attempts": {Type: "integer"}, "reason": str(), "detail": str(), "rollback_ref": str(),
		"idempotency_key": str(), "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "tenant_id", "destination", "connector", "target", "status", "attempts", "created_at", "updated_at")
	rotationRun := object(map[string]*Schema{
		"id": uuid(), "tenant_id": uuid(), "identity_id": uuid(), "outbox_id": {Type: "integer"},
		"status":  {Type: "string", Enum: []string{"running", "succeeded", "failed"}},
		"trigger": str(), "reason": str(), "predecessor_fingerprint": str(),
		"successor_fingerprint": str(), "rollback_ref": str(), "error": str(),
		"idempotency_key": str(), "created_at": timestamp(), "updated_at": timestamp(),
		"completed_at": timestamp(),
	}, "id", "tenant_id", "identity_id", "status", "trigger", "created_at", "updated_at")
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
	graphQueryResult := object(map[string]*Schema{
		"rows": {Type: "array", Items: &Schema{Type: "object"}},
	}, "rows")

	agent := object(map[string]*Schema{
		"id": uuid(), "name": str(), "status": str(), "version": str(), "last_seen_at": timestamp(),
	}, "id", "name", "status")
	agentList := object(map[string]*Schema{
		"agents":      {Type: "array", Items: ref("Agent")},
		"next_cursor": str(),
	}, "agents")
	enrollmentToken := object(map[string]*Schema{
		"token": str(), "enroll_path": str(),
	}, "token")
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
	secretMeta := object(map[string]*Schema{
		"name": str(), "version": {Type: "integer"}, "created_at": timestamp(), "updated_at": timestamp(),
	}, "name", "version")
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
	mcpToolList := object(map[string]*Schema{
		"identity":  str(),
		"read_only": {Type: "boolean"},
		"tools":     {Type: "array", Items: str()},
	}, "read_only", "tools")
	mcpToolCall := object(map[string]*Schema{
		"subject": str(),
	})
	mcpToolResult := object(map[string]*Schema{
		"tool":      str(),
		"citations": {Type: "array", Items: str()},
		"text":      str(),
	}, "tool", "text")

	return map[string]*Schema{
		"Problem":                  problemSchema,
		"Agent":                    agent,
		"AgentList":                agentList,
		"EnrollmentToken":          enrollmentToken,
		"RiskComponents":           riskComponents,
		"CredentialRisk":           credentialRisk,
		"CredentialRiskList":       credentialRiskList,
		"Certificate":              certificate,
		"CertificateIngest":        certificateIngest,
		"CertificateList":          list("Certificate"),
		"DiscoverySource":          discoverySource,
		"DiscoverySourceRequest":   discoverySourceReq,
		"DiscoverySourceList":      list("DiscoverySource"),
		"DiscoverySchedule":        discoverySchedule,
		"DiscoveryScheduleRequest": discoveryScheduleReq,
		"DiscoveryScheduleList":    list("DiscoverySchedule"),
		"DiscoveryRun":             discoveryRun,
		"DiscoveryRunRequest":      discoveryRunReq,
		"DiscoveryRunList":         list("DiscoveryRun"),
		"DiscoveryFinding":         discoveryFinding,
		"DiscoveryFindingList":     list("DiscoveryFinding"),
		"ConnectorCatalogItem":     connectorCatalogItem,
		"ConnectorCatalog":         connectorCatalog,
		"ConnectorDelivery":        connectorDelivery,
		"ConnectorDeliveryList":    list("ConnectorDelivery"),
		"RotationRun":              rotationRun,
		"RotationRunList":          list("RotationRun"),
		"Role":                     role,
		"RoleList":                 list("Role"),
		"OIDCTenantMapping":        oidcTenantMapping,
		"OIDCMappingStatus":        oidcMappingStatus,
		"Member":                   member,
		"MemberRequest":            memberReq,
		"MemberList":               list("Member"),
		"OffboardMemberRequest":    offboardMemberReq,
		"OffboardMemberResponse":   offboardMemberResp,
		"APIToken":                 apiToken,
		"APITokenList":             list("APIToken"),
		"APITokenCreateRequest":    apiTokenCreateReq,
		"APITokenCreateResponse":   apiTokenCreateResp,
		"APITokenRevokeRequest":    apiTokenRevokeReq,
		"AuditEvent":               auditEvent,
		"AuditEventList":           auditEventList,
		"AuditBundle":              auditBundle,
		"GraphNode":                graphNode,
		"GraphEdge":                graphEdge,
		"GraphResponse":            graphResponse,
		"GraphReachable":           graphReachable,
		"GraphImpact":              graphImpact,
		"GraphQueryResult":         graphQueryResult,
		"Owner":                    owner,
		"OwnerRequest":             ownerReq,
		"OwnerList":                list("Owner"),
		"Profile":                  profile,
		"ProfileRequest":           profileReq,
		"ProfileList":              list("Profile"),
		"Issuer":                   issuer,
		"IssuerRequest":            issuerReq,
		"IssuerList":               list("Issuer"),
		"Identity":                 identity,
		"IdentityRequest":          identityReq,
		"IdentityList":             list("Identity"),
		"TransitionRequest":        transitionReq,
		"ApprovalRequest":          approvalReq,
		"Approval":                 approval,
		"SecretRequest":            secretReq,
		"SecretMeta":               secretMeta,
		"SecretMetaList":           list("SecretMeta"),
		"SecretValue":              secretValue,
		"ShareRequest":             shareReq,
		"ShareToken":               shareToken,
		"ShareRedeemRequest":       shareRedeemReq,
		"ShareValue":               shareValue,
		"PKISecretRequest":         pkiSecretReq,
		"PKISecret":                pkiSecret,
		"MachineLoginRequest":      machineLoginReq,
		"MachineLoginResponse":     machineLoginResp,
		"AIQueryRequest":           aiQueryReq,
		"RCARequest":               rcaReq,
		"AIAnswer":                 aiAnswer,
		"MCPToolList":              mcpToolList,
		"MCPToolCall":              mcpToolCall,
		"MCPToolResult":            mcpToolResult,
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
