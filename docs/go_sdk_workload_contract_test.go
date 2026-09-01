// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type sdkOpenAPISchema struct {
	Ref string `json:"$ref"`
}

type sdkOpenAPIMedia struct {
	Schema sdkOpenAPISchema `json:"schema"`
}

type sdkOpenAPIContent struct {
	Content map[string]sdkOpenAPIMedia `json:"content"`
}

type sdkOpenAPIOperation struct {
	Parameters []struct {
		Name     string `json:"name"`
		In       string `json:"in"`
		Required bool   `json:"required"`
	} `json:"parameters"`
	RequestBody *sdkOpenAPIContent           `json:"requestBody"`
	Responses   map[string]sdkOpenAPIContent `json:"responses"`
}

type sdkOpenAPIDocument struct {
	Paths map[string]map[string]sdkOpenAPIOperation `json:"paths"`
}

type sdkOperationContract struct {
	method       string
	path         string
	requestRef   string
	responseRefs map[string]string
	idempotent   bool
}

// TestGoSDKWorkloadSurfaceTracksServedContract prevents the handwritten,
// stdlib-only Go client from quietly falling behind the generated contract.
// It binds callable methods, byte-slice proof custody, routes, exact success
// statuses, schema names, and public docs into one permanent release oracle.
func TestGoSDKWorkloadSurfaceTracksServedContract(t *testing.T) {
	t.Parallel()

	contracts := []sdkOperationContract{
		{httpPost, "/api/v1/broker/agent-identities/preview", "BrokerAgentIdentityRequest", map[string]string{"200": "BrokerAgentIdentityPreview"}, false},
		{httpPost, "/api/v1/broker/agent-identities", "BrokerAgentIdentityRequest", map[string]string{"201": "BrokerAgentIdentity"}, true},
		{httpGet, "/api/v1/broker/agent-identities", "", map[string]string{"200": "BrokerAgentIdentityHistoryList"}, false},
		{httpGet, "/api/v1/broker/agent-identities/{id}", "", map[string]string{"200": "BrokerAgentIdentityHistory"}, false},
		{httpPost, "/api/v1/workloads/attested-issuance/preview", "AttestedSVIDRequest", map[string]string{"200": "AttestedSVIDPreview"}, false},
		{httpPost, "/api/v1/workloads/attested-issuance", "AttestedSVIDRequest", map[string]string{"201": "AttestedSVID"}, true},
		{httpPost, "/api/v1/ephemeral/preview", "EphemeralCredentialRequest", map[string]string{"200": "EphemeralCredentialPreview"}, false},
		{httpPost, "/api/v1/ephemeral", "EphemeralCredentialRequest", map[string]string{"201": "EphemeralCredential", "202": "EphemeralCredential"}, true},
		{httpPost, "/api/v1/ephemeral/{id}/approvals", "EphemeralApprovalRequest", map[string]string{"200": "EphemeralApproval"}, true},
	}

	raw, err := os.ReadFile("../clients/sdk/openapi.json")
	if err != nil {
		t.Fatalf("read pinned SDK OpenAPI: %v", err)
	}
	var doc sdkOpenAPIDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode pinned SDK OpenAPI: %v", err)
	}
	for _, contract := range contracts {
		op, ok := doc.Paths[contract.path][contract.method]
		if !ok {
			t.Errorf("pinned OpenAPI is missing %s %s", strings.ToUpper(contract.method), contract.path)
			continue
		}
		if contract.requestRef != "" {
			if op.RequestBody == nil {
				t.Errorf("%s %s has no request body", strings.ToUpper(contract.method), contract.path)
			} else if got := schemaName(op.RequestBody.Content["application/json"].Schema.Ref); got != contract.requestRef {
				t.Errorf("%s %s request schema = %q, want %q", strings.ToUpper(contract.method), contract.path, got, contract.requestRef)
			}
		}
		for status, wantSchema := range contract.responseRefs {
			response, ok := op.Responses[status]
			if !ok {
				t.Errorf("%s %s is missing success status %s", strings.ToUpper(contract.method), contract.path, status)
				continue
			}
			if got := schemaName(response.Content["application/json"].Schema.Ref); got != wantSchema {
				t.Errorf("%s %s response %s schema = %q, want %q", strings.ToUpper(contract.method), contract.path, status, got, wantSchema)
			}
		}
		hasIdempotency := false
		for _, parameter := range op.Parameters {
			if parameter.In == "header" && parameter.Name == "Idempotency-Key" && parameter.Required {
				hasIdempotency = true
			}
		}
		if hasIdempotency != contract.idempotent {
			t.Errorf("%s %s required Idempotency-Key = %v, want %v", strings.ToUpper(contract.method), contract.path, hasIdempotency, contract.idempotent)
		}
	}

	methods, fields := parseGoSDKWorkloadSurface(t)
	for _, want := range []string{
		"PreviewBrokerAgentIdentity", "IssueBrokerAgentIdentity", "IssueBrokerAgentIdentityKeyed",
		"ListBrokerAgentIdentities", "BrokerAgentIdentities", "GetBrokerAgentIdentity",
		"PreviewAttestedSVID", "IssueAttestedSVID", "IssueAttestedSVIDKeyed",
		"PreviewEphemeralCredential", "IssueEphemeralCredential", "IssueEphemeralCredentialKeyed",
		"ApproveEphemeralCredential", "ApproveEphemeralCredentialKeyed",
	} {
		if !methods[want] {
			t.Errorf("supported Go SDK is missing callable method %s", want)
		}
	}
	for _, check := range []struct {
		structName string
		fieldName  string
		wantType   string
		wantJSON   string
	}{
		{"BrokerAgentIdentityRequest", "Payload", "[]byte", "payload_base64"},
		{"BrokerAgentIdentityRequest", "TaskEnvelope", "[]byte", "task_envelope_base64"},
		{"BrokerAgentIdentityRequest", "TTLSeconds", "int64", "ttl_seconds"},
		{"AttestedSVIDRequest", "Payload", "[]byte", "payload_base64"},
		{"AttestedSVIDRequest", "TTLSeconds", "int64", "ttl_seconds"},
		{"EphemeralCredentialRequest", "Payload", "[]byte", "payload_base64"},
		{"EphemeralCredentialRequest", "TTLSeconds", "int64", "ttl_seconds"},
		{"BrokerAgentIdentity", "SPIFFEID", "*string", "spiffe_id"},
		{"AttestedSVID", "SPIFFEID", "*string", "spiffe_id"},
		{"EphemeralCredential", "SPIFFEID", "*string", "spiffe_id"},
		{"BrokerAgentIdentityHistory", "SPIFFEID", "*string", "spiffe_id"},
	} {
		field, ok := fields[check.structName][check.fieldName]
		if !ok {
			t.Errorf("Go SDK struct %s is missing field %s", check.structName, check.fieldName)
			continue
		}
		if field.goType != check.wantType || field.jsonName != check.wantJSON {
			t.Errorf("Go SDK %s.%s = type %s json %q, want type %s json %q",
				check.structName, check.fieldName, field.goType, field.jsonName, check.wantType, check.wantJSON)
		}
	}

	readme := read(t, "../clients/sdk/README.md")
	clientDocs := read(t, "features/client-sdks.md")
	workloadDocs := read(t, "features/workload-identity.md")
	for path, text := range map[string]string{
		"clients/sdk/README.md":              readme,
		"docs/features/client-sdks.md":       clientDocs,
		"docs/features/workload-identity.md": workloadDocs,
	} {
		for _, want := range []string{"PreviewBrokerAgentIdentity", "IssueBrokerAgentIdentityKeyed", "IssueEphemeralCredentialKeyed"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not document callable Go workload method %s", path, want)
			}
		}
	}
	if strings.Contains(workloadDocs, "does not yet provide these workload methods") {
		t.Error("workload identity docs still claim the callable Go SDK workload surface is missing")
	}
	for _, want := range []string{"caller-owned", "[]byte", "wipes", "refuse redirects", "SPIFFEID"} {
		if !strings.Contains(readme+clientDocs+workloadDocs, want) {
			t.Errorf("Go SDK workload documentation lost safety disclosure %q", want)
		}
	}
}

const (
	httpGet  = "get"
	httpPost = "post"
)

type sdkGoField struct {
	goType   string
	jsonName string
}

func parseGoSDKWorkloadSurface(t *testing.T) (map[string]bool, map[string]map[string]sdkGoField) {
	t.Helper()
	path := "../clients/sdk/go/trstctl/workloads.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	methods := map[string]bool{}
	fields := map[string]map[string]sdkGoField{}
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Recv != nil {
				methods[declaration.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				fields[typeSpec.Name.Name] = map[string]sdkGoField{}
				for _, field := range structType.Fields.List {
					if len(field.Names) != 1 || field.Tag == nil {
						continue
					}
					var typeText bytes.Buffer
					if err := format.Node(&typeText, fset, field.Type); err != nil {
						t.Fatalf("format %s.%s type: %v", typeSpec.Name.Name, field.Names[0].Name, err)
					}
					tag, err := strconv.Unquote(field.Tag.Value)
					if err != nil {
						t.Fatalf("unquote %s.%s tag: %v", typeSpec.Name.Name, field.Names[0].Name, err)
					}
					jsonName := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
					fields[typeSpec.Name.Name][field.Names[0].Name] = sdkGoField{goType: typeText.String(), jsonName: jsonName}
				}
			}
		}
	}
	return methods, fields
}

func schemaName(ref string) string {
	return strings.TrimPrefix(ref, "#/components/schemas/")
}
