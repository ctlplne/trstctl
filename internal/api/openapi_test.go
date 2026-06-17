package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// fetchSpec starts the API (no dependencies needed for the static spec) and
// returns the parsed /api/v1/openapi.json document.
func fetchSpec(t *testing.T) map[string]any {
	t.Helper()
	srv := httptest.NewServer(api.New(nil, nil, nil))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/openapi.json")
	if err != nil {
		t.Fatalf("GET openapi.json: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("openapi.json content-type = %q, want json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	return doc
}

// TestOpenAPISpecGeneratedAndValid is the acceptance: the spec is generated and
// structurally valid OpenAPI 3.1.
func TestOpenAPISpecGeneratedAndValid(t *testing.T) {
	doc := fetchSpec(t)

	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", doc["openapi"])
	}
	info, ok := doc["info"].(map[string]any)
	if !ok || info["title"] == "" || info["version"] == "" {
		t.Fatalf("info = %v, want title+version", doc["info"])
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) < 7 {
		t.Fatalf("paths has %d entries, want >= 7", len(paths))
	}
	components, ok := doc["components"].(map[string]any)
	if !ok {
		t.Fatal("missing components")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok || schemas["Problem"] == nil {
		t.Fatalf("components.schemas missing Problem: %v", components["schemas"])
	}

	// Every operation must declare at least one response, and every $ref must
	// resolve to a defined schema.
	methods := map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true}
	for p, pi := range paths {
		ops := pi.(map[string]any)
		for m, raw := range ops {
			if !methods[m] {
				continue
			}
			op := raw.(map[string]any)
			if op["operationId"] == nil || op["operationId"] == "" {
				t.Errorf("%s %s: missing operationId", strings.ToUpper(m), p)
			}
			resps, ok := op["responses"].(map[string]any)
			if !ok || len(resps) == 0 {
				t.Errorf("%s %s: no responses", strings.ToUpper(m), p)
			}
		}
	}
	for _, ref := range collectRefs(doc) {
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(ref, prefix) {
			t.Errorf("unexpected $ref form: %s", ref)
			continue
		}
		if schemas[strings.TrimPrefix(ref, prefix)] == nil {
			t.Errorf("$ref %s does not resolve to a defined schema", ref)
		}
	}
}

// TestOpenAPISpecCoversRoutes proves the spec is generated from the real routes:
// every served API route appears in the document.
func TestOpenAPISpecCoversRoutes(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)

	for _, rt := range api.New(nil, nil, nil).Routes() {
		if rt.Path == "/api/v1/openapi.json" {
			continue
		}
		pi, ok := paths[rt.Path].(map[string]any)
		if !ok {
			t.Errorf("route %s %s not documented (path missing)", rt.Method, rt.Path)
			continue
		}
		if pi[strings.ToLower(rt.Method)] == nil {
			t.Errorf("route %s %s not documented (method missing)", rt.Method, rt.Path)
		}
	}
}

func TestOpenAPISpecCoversMachineLogin(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)
	rawPath, ok := paths["/api/v1/secrets/login"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI spec is missing POST /api/v1/secrets/login")
	}
	op, ok := rawPath["post"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI spec is missing POST operation for /api/v1/secrets/login")
	}
	if got := op["operationId"]; got != "machineLogin" {
		t.Fatalf("machine-login operationId = %v, want machineLogin", got)
	}
	reqRef := op["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if reqRef != "#/components/schemas/MachineLoginRequest" {
		t.Fatalf("machine-login request schema = %v", reqRef)
	}
	respRef := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if respRef != "#/components/schemas/MachineLoginResponse" {
		t.Fatalf("machine-login response schema = %v", respRef)
	}
}

func TestOpenAPIPathParameterSchemas(t *testing.T) {
	doc := fetchSpec(t)

	assertPathParamSchema(t, doc, "get", "/api/v1/owners/{id}", "id", "string", "uuid")
	assertPathParamSchema(t, doc, "get", "/api/v1/profiles/{name}/versions/{version}", "name", "string", "")
	assertPathParamSchema(t, doc, "get", "/api/v1/profiles/{name}/versions/{version}", "version", "integer", "")
	assertPathParamSchema(t, doc, "get", "/api/v1/graph/reachable/{id}", "id", "string", "")
	assertPathParamSchema(t, doc, "post", "/api/v1/mcp/tools/{tool}", "tool", "string", "")
	assertPathParamSchema(t, doc, "get", "/api/v1/secrets/store/{name}", "name", "string", "")
}

func TestNoManualAPIV1MuxRoutesBypassOpenAPI(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("read api.go: %v", err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("[A-Z]+\s+(/api/v1/[^"]+)"`)
	if matches := re.FindAllStringSubmatch(string(src), -1); len(matches) > 0 {
		var paths []string
		for _, m := range matches {
			paths = append(paths, m[1])
		}
		t.Fatalf("literal /api/v1 mux registrations bypass the route registry/OpenAPI: %s", strings.Join(paths, ", "))
	}
}

func assertPathParamSchema(t *testing.T, doc map[string]any, method, path, name, wantType, wantFormat string) {
	t.Helper()
	paths := doc["paths"].(map[string]any)
	pathItem, ok := paths[path].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI spec is missing path %s", path)
	}
	op, ok := pathItem[method].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI spec is missing %s %s", strings.ToUpper(method), path)
	}
	params, ok := op["parameters"].([]any)
	if !ok {
		t.Fatalf("%s %s has no parameters", strings.ToUpper(method), path)
	}
	for _, raw := range params {
		p := raw.(map[string]any)
		if p["name"] != name || p["in"] != "path" {
			continue
		}
		schema := p["schema"].(map[string]any)
		if got := schema["type"]; got != wantType {
			t.Fatalf("%s %s path param %s type = %v, want %s", strings.ToUpper(method), path, name, got, wantType)
		}
		if wantFormat == "" {
			if got, ok := schema["format"]; ok {
				t.Fatalf("%s %s path param %s format = %v, want omitted", strings.ToUpper(method), path, name, got)
			}
			return
		}
		if got := schema["format"]; got != wantFormat {
			t.Fatalf("%s %s path param %s format = %v, want %s", strings.ToUpper(method), path, name, got, wantFormat)
		}
		return
	}
	t.Fatalf("%s %s missing path parameter %s", strings.ToUpper(method), path, name)
}

// collectRefs walks an arbitrary decoded JSON value and returns every $ref.
func collectRefs(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "$ref" {
				if s, ok := val.(string); ok {
					out = append(out, s)
				}
				continue
			}
			out = append(out, collectRefs(val)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, collectRefs(e)...)
		}
	}
	return out
}
