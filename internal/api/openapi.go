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
	OperationID string              `json:"operationId"`
	Summary     string              `json:"summary,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
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

// Components holds reusable schemas.
type Components struct {
	Schemas map[string]*Schema `json:"schemas"`
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
			Title:       "certctl API",
			Version:     "v1",
			Description: "Resource-oriented REST API for certctl. Mutations require an Idempotency-Key; errors are RFC 7807 problem+json; lists use cursor pagination.",
		},
		Paths:      map[string]PathItem{},
		Components: Components{Schemas: componentSchemas()},
	}
	for _, r := range routes {
		if r.path == specPath {
			continue
		}
		pi := doc.Paths[r.path]
		if pi == nil {
			pi = PathItem{}
			doc.Paths[r.path] = pi
		}
		op := &Operation{OperationID: r.opID, Summary: r.summary, Responses: map[string]Response{}}
		for _, pp := range r.pathParams {
			op.Parameters = append(op.Parameters, Parameter{Name: pp, In: "path", Required: true, Schema: uuid()})
		}
		for _, q := range r.query {
			op.Parameters = append(op.Parameters, Parameter{Name: q.name, In: "query", Description: q.desc, Schema: &Schema{Type: q.typ}})
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

	list := func(item string) *Schema {
		return object(map[string]*Schema{
			"items":       {Type: "array", Items: ref(item)},
			"next_cursor": str(),
		}, "items")
	}

	problemSchema := object(map[string]*Schema{
		"type": str(), "title": str(), "status": {Type: "integer"}, "detail": str(), "instance": str(),
	})

	return map[string]*Schema{
		"Problem":           problemSchema,
		"Owner":             owner,
		"OwnerRequest":      ownerReq,
		"OwnerList":         list("Owner"),
		"Issuer":            issuer,
		"IssuerRequest":     issuerReq,
		"IssuerList":        list("Issuer"),
		"Identity":          identity,
		"IdentityRequest":   identityReq,
		"IdentityList":      list("Identity"),
		"TransitionRequest": transitionReq,
	}
}

// openapiHandler serves the generated OpenAPI 3.1 document.
func (a *API) openapiHandler(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.spec)
}
