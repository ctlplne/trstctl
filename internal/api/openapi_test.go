// SPDX-License-Identifier: MPL-2.0

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

func TestOpenAPISecretRotationReportsQueuedDeferredAndUnavailableModesTruthfully(t *testing.T) {
	doc := fetchSpec(t)
	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)

	rotation := schemas["SecretRotation"].(map[string]any)
	required := rotation["required"].([]any)
	hasRequired := func(name string) bool {
		for _, item := range required {
			if item == name {
				return true
			}
		}
		return false
	}
	if !hasRequired("queued") {
		t.Fatalf("SecretRotation required=%v, want queued so clients cannot infer completion", required)
	}
	statuses := schemas["SecretRotationSchedule"].(map[string]any)["properties"].(map[string]any)["last_run_status"].(map[string]any)["enum"].([]any)
	if len(statuses) == 0 || statuses[0] != "" {
		t.Fatalf("SecretRotationSchedule last_run_status=%v, want explicit never-run sentinel", statuses)
	}
	for _, want := range []string{"rolled_back", "rollback_failed", "retire_pending", "delivery_failed", "unsupported"} {
		found := false
		for _, status := range statuses {
			found = found || status == want
		}
		if !found {
			t.Fatalf("SecretRotationSchedule last_run_status=%v, missing %q", statuses, want)
		}
	}
	runStatuses := schemas["SecretRotationScheduleRun"].(map[string]any)["properties"].(map[string]any)["status"].(map[string]any)["enum"].([]any)
	for _, status := range runStatuses {
		if status == "" {
			t.Fatalf("SecretRotationScheduleRun status=%v, actual run records cannot be empty", runStatuses)
		}
	}
	runRequired := schemas["SecretRotationScheduleRun"].(map[string]any)["required"].([]any)
	hasReconciled := false
	for _, field := range runRequired {
		hasReconciled = hasReconciled || field == "reconciled"
	}
	if !hasReconciled {
		t.Fatalf("SecretRotationScheduleRun required=%v, want reconciliation truth", runRequired)
	}

	request := schemas["SecretRotationRequest"].(map[string]any)
	requestProps := request["properties"].(map[string]any)
	providerDescription, _ := requestProps["provider"].(map[string]any)["description"].(string)
	ttlDescription, _ := requestProps["ttl_seconds"].(map[string]any)["description"].(string)
	if !strings.Contains(providerDescription, "unavailable") || !strings.Contains(providerDescription, "503") {
		t.Fatalf("rotation provider description=%q, want dynamic unavailable 503", providerDescription)
	}
	if !strings.Contains(ttlDescription, "Connector requests reject") ||
		!strings.Contains(ttlDescription, "400") ||
		!strings.Contains(ttlDescription, "unavailable with 503") {
		t.Fatalf("rotation ttl description=%q, want connector rejection plus provider refusal", ttlDescription)
	}
	scheduleRequest := schemas["SecretRotationScheduleRequest"].(map[string]any)
	scheduleProviderDescription, _ := scheduleRequest["properties"].(map[string]any)["provider"].(map[string]any)["description"].(string)
	if !strings.Contains(scheduleProviderDescription, "connector:<target> only") ||
		!strings.Contains(scheduleProviderDescription, "503") {
		t.Fatalf("schedule provider description=%q, want connector-only fail-closed contract", scheduleProviderDescription)
	}

	due := schemas["SecretRotationDueRun"].(map[string]any)
	dueProps := due["properties"].(map[string]any)
	for _, field := range []string{
		"scanned", "deferred", "run_limit_reached", "scan_limit_reached",
		"complete", "partial", "failed_schedule_id", "system_error",
	} {
		if dueProps[field] == nil {
			t.Fatalf("SecretRotationDueRun missing truthful %s evidence: %v", field, dueProps)
		}
	}
	if description, _ := dueProps["ran"].(map[string]any)["description"].(string); !strings.Contains(description, "50") {
		t.Fatalf("SecretRotationDueRun ran description=%q, want run bound", description)
	}
	if description, _ := dueProps["scanned"].(map[string]any)["description"].(string); !strings.Contains(description, "500") {
		t.Fatalf("SecretRotationDueRun scanned description=%q, want scan bound", description)
	}
	deferred := schemas["SecretRotationScheduleDeferred"].(map[string]any)
	deferredProps := deferred["properties"].(map[string]any)
	reasons := deferredProps["reason"].(map[string]any)["enum"].([]any)
	if len(reasons) != 4 || reasons[0] != "approval_pending" || reasons[1] != "command_in_flight" ||
		reasons[2] != "command_claimed" || reasons[3] != "config_revision_unanchored" ||
		deferredProps["error"] == nil {
		t.Fatalf("deferred reasons=%v, want closed row-local reason set", reasons)
	}
	if description, _ := dueProps["system_error"].(map[string]any)["description"].(string); !strings.Contains(description, "same key") || !strings.Contains(description, "new key") {
		t.Fatalf("SecretRotationDueRun system_error description=%q, want exact replay/continuation contract", description)
	}
	responses := doc["paths"].(map[string]any)["/api/v1/secrets/rotation-schedules/run-due"].(map[string]any)["post"].(map[string]any)["responses"].(map[string]any)
	unavailable := responses["503"].(map[string]any)
	content := unavailable["content"].(map[string]any)
	jsonRef := content["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	problemRef := content["application/problem+json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if jsonRef != "#/components/schemas/SecretRotationDueRun" || problemRef != "#/components/schemas/Problem" {
		t.Fatalf("run-due 503 content=%v, want typed cached receipt and generic problem variants", content)
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

func TestApplicationSecretImportContractIsExplicitlyUnavailable(t *testing.T) {
	doc := fetchSpec(t)
	op := doc["paths"].(map[string]any)["/api/v1/secrets/store/import"].(map[string]any)["post"].(map[string]any)
	if op["deprecated"] != true || op["x-trstctl-availability"] != "unavailable" {
		t.Fatalf("secret import availability = deprecated:%v state:%v, want explicit unavailable", op["deprecated"], op["x-trstctl-availability"])
	}
	if reason, _ := op["x-trstctl-unavailable-reason"].(string); !strings.Contains(reason, "Event-sourced atomic batch import") {
		t.Fatalf("secret import unavailable reason = %q", reason)
	}
	responses := op["responses"].(map[string]any)
	if responses["501"] == nil || responses["201"] != nil {
		t.Fatalf("secret import responses = %v, want 501 and no success response", responses)
	}
}

func TestOpenAPIMutationsDeclareRequiredIdempotencyKeyHeader(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)

	for _, rt := range api.New(nil, nil, nil).Routes() {
		if !rt.Mutation {
			continue
		}
		pathItem, ok := paths[openAPIPathForTest(rt.Path)].(map[string]any)
		if !ok {
			t.Fatalf("mutation route %s %s is missing from OpenAPI", rt.Method, rt.Path)
		}
		op, ok := pathItem[strings.ToLower(rt.Method)].(map[string]any)
		if !ok {
			t.Fatalf("mutation route %s %s is missing its OpenAPI operation", rt.Method, rt.Path)
		}
		if !hasRequiredHeaderParam(op, "Idempotency-Key") {
			t.Errorf("mutation route %s %s (%s) does not declare required Idempotency-Key header", rt.Method, rt.Path, rt.OperationID)
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

func TestOpenAPISpecCoversRiskDashboardContract(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)
	rawPath, ok := paths["/api/v1/risk/credentials"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI spec is missing GET /api/v1/risk/credentials")
	}
	op, ok := rawPath["get"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI spec is missing GET operation for /api/v1/risk/credentials")
	}
	if got := op["operationId"]; got != "listRiskScores" {
		t.Fatalf("risk operationId = %v, want listRiskScores", got)
	}
	respRef := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if respRef != "#/components/schemas/CredentialRiskList" {
		t.Fatalf("risk response schema = %v, want CredentialRiskList", respRef)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	if schemas["CredentialRisk"] == nil || schemas["RiskComponents"] == nil || schemas["CredentialRiskList"] == nil {
		t.Fatalf("risk dashboard schemas missing from OpenAPI components")
	}
}

func TestOpenAPISpecCoversImmutableApprovalQueueContract(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)

	list := paths["/api/v1/approval-requests"].(map[string]any)["get"].(map[string]any)
	if got := list["operationId"]; got != "listApprovalRequests" {
		t.Fatalf("approval-request list operationId = %v, want listApprovalRequests", got)
	}
	for _, parameter := range []string{"status", "limit", "cursor"} {
		if !hasQueryParam(list, parameter) {
			t.Fatalf("approval-request list is missing the %s query parameter", parameter)
		}
	}
	listRef := list["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if listRef != "#/components/schemas/ApprovalRequestList" {
		t.Fatalf("approval-request list response schema = %v, want ApprovalRequestList", listRef)
	}

	approve := paths["/api/v1/approval-requests/{id}/approvals"].(map[string]any)["post"].(map[string]any)
	requestRef := approve["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if requestRef != "#/components/schemas/ApprovalDecisionInput" {
		t.Fatalf("approval decision request schema = %v, want ApprovalDecisionInput", requestRef)
	}
	responseRef := approve["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if responseRef != "#/components/schemas/ApprovalDecision" {
		t.Fatalf("approval decision response schema = %v, want ApprovalDecision", responseRef)
	}
	deny := paths["/api/v1/approval-requests/{id}/denials"].(map[string]any)["post"].(map[string]any)
	denialRequestRef := deny["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if denialRequestRef != "#/components/schemas/ApprovalDenialInput" {
		t.Fatalf("approval denial request schema = %v, want ApprovalDenialInput", denialRequestRef)
	}

	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	assertRequiredSchemaFields(t, schemas, "ApprovalDecisionInput", "intent_digest")
	assertRequiredSchemaFields(t, schemas, "ApprovalDenialInput", "intent_digest", "reason")
	assertRequiredSchemaFields(t, schemas, "PendingApprovalRequest",
		"id", "intent_digest", "resource_id", "resource_name", "resource_kind", "action", "requester",
		"target_version", "evidence_refs", "approval_count", "required_approvals", "status", "created_at", "expires_at",
	)
	assertSchemaProperty(t, schemas, "ApprovalRequestList", "next_cursor", "string", "")
	actionSchema := schemas["PendingApprovalRequest"].(map[string]any)["properties"].(map[string]any)["action"].(map[string]any)
	actions := actionSchema["enum"].([]any)
	for _, want := range []string{"issue", "create", "rotate", "recover", "delete", "managedkey:zeroize"} {
		found := false
		for _, got := range actions {
			found = found || got == want
		}
		if !found {
			t.Errorf("PendingApprovalRequest.action enum = %v, missing %q", actions, want)
		}
	}
	// The identity-specific compatibility route is additive, but it must bind
	// every decision to the exact immutable request rather than infer one.
	assertRequiredSchemaFields(t, schemas, "ApprovalRequest", "action", "request_id", "intent_digest")
	assertRequiredSchemaFields(t, schemas, "SecretApprovalRequest", "action", "request_id", "intent_digest")
	assertRequiredSchemaFields(t, schemas, "ManagedKeyApprovalRequest", "key_id", "action", "request_id", "intent_digest")
	assertRequiredSchemaFields(t, schemas, "EphemeralApprovalRequest", "action", "request_id", "intent_digest")
	assertRequiredSchemaFields(t, schemas, "EphemeralCredential", "request_id", "approval_request_id", "intent_digest")
	assertRequiredSchemaFields(t, schemas, "EphemeralApproval",
		"id", "intent_digest", "resource", "action", "approver", "approvals", "approval_count", "required_approvals", "status",
	)
	assertSchemaProperty(t, schemas, "EphemeralCredential", "approval_request_id", "string", "uuid")
	assertSchemaProperty(t, schemas, "EphemeralApprovalRequest", "request_id", "string", "uuid")
	assertSchemaProperty(t, schemas, "EphemeralApproval", "id", "string", "uuid")
}

func TestOpenAPIPathParameterSchemas(t *testing.T) {
	doc := fetchSpec(t)

	assertPathParamSchema(t, doc, "get", "/api/v1/owners/{id}", "id", "string", "uuid")
	assertPathParamSchema(t, doc, "get", "/api/v1/profiles/{name}/versions/{version}", "name", "string", "")
	assertPathParamSchema(t, doc, "get", "/api/v1/profiles/{name}/versions/{version}", "version", "integer", "")
	assertPathParamSchema(t, doc, "get", "/api/v1/graph/reachable/{id}", "id", "string", "")
	assertPathParamSchema(t, doc, "post", "/api/v1/mcp/tools/{tool}", "tool", "string", "")
	assertPathParamSchema(t, doc, "get", "/api/v1/secrets/store/{name}", "name", "string", "")
	assertPathParamSchema(t, doc, "post", "/api/v1/ephemeral/{id}/approvals", "id", "string", "uuid")
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

func hasRequiredHeaderParam(op map[string]any, name string) bool {
	params, _ := op["parameters"].([]any)
	for _, raw := range params {
		p, _ := raw.(map[string]any)
		if p["name"] == name && p["in"] == "header" && p["required"] == true {
			return true
		}
	}
	return false
}

func hasQueryParam(op map[string]any, name string) bool {
	params, _ := op["parameters"].([]any)
	for _, raw := range params {
		p, _ := raw.(map[string]any)
		if p["name"] == name && p["in"] == "query" {
			return true
		}
	}
	return false
}

func assertRequiredSchemaFields(t *testing.T, schemas map[string]any, name string, fields ...string) {
	t.Helper()
	schema, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI components are missing schema %s", name)
	}
	required, _ := schema["required"].([]any)
	set := make(map[string]bool, len(required))
	for _, raw := range required {
		field, _ := raw.(string)
		set[field] = true
	}
	for _, field := range fields {
		if !set[field] {
			t.Errorf("OpenAPI schema %s does not require %s", name, field)
		}
	}
}

func assertSchemaProperty(t *testing.T, schemas map[string]any, name, property, wantType, wantFormat string) {
	t.Helper()
	schema, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI components are missing schema %s", name)
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI schema %s has no properties", name)
	}
	propertySchema, ok := properties[property].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI schema %s is missing property %s", name, property)
	}
	if got := propertySchema["type"]; got != wantType {
		t.Fatalf("OpenAPI schema %s property %s type = %v, want %s", name, property, got, wantType)
	}
	if got := propertySchema["format"]; got != wantFormat && !(wantFormat == "" && got == nil) {
		t.Fatalf("OpenAPI schema %s property %s format = %v, want %s", name, property, got, wantFormat)
	}
}

func openAPIPathForTest(path string) string {
	return strings.ReplaceAll(path, "...}", "}")
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
