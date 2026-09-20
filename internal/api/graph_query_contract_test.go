// SPDX-License-Identifier: BUSL-1.1
package api_test

import "testing"

func TestGraphQueryContractSuppliesRequiredEditorInput(t *testing.T) {
	doc := fetchSpec(t)
	op := doc["paths"].(map[string]any)["/api/v1/graph/query"].(map[string]any)["post"].(map[string]any)
	body, ok := op["requestBody"].(map[string]any)
	if !ok || body["required"] != true {
		t.Fatal("graph query has no required request body; the generated playground cannot send its query")
	}
	schema := body["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if schema["$ref"] != "#/components/schemas/GraphQueryRequest" {
		t.Fatalf("query request reference = %v", schema)
	}
	request := doc["components"].(map[string]any)["schemas"].(map[string]any)["GraphQueryRequest"].(map[string]any)
	query := request["properties"].(map[string]any)["query"].(map[string]any)
	if query["type"] != "string" || query["minLength"] != float64(1) {
		t.Fatalf("query must be a non-empty string: %v", query)
	}
	required := request["required"].([]any)
	if len(required) != 1 || required[0] != "query" {
		t.Fatalf("required fields = %v", required)
	}
}

func TestGraphQueryContractIsReadOnlyWithoutWeakeningWrites(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)
	op := paths["/api/v1/graph/query"].(map[string]any)["post"].(map[string]any)
	if op["x-trstctl-read-only"] != true || op["x-trstctl-permission"] != "graph:read" {
		t.Errorf("graph query needs explicit read-only metadata and graph:read permission")
	}
	for path, value := range paths {
		for method, raw := range value.(map[string]any) {
			operation := raw.(map[string]any)
			parameters, _ := operation["parameters"].([]any)
			for _, p := range parameters {
				parameter := p.(map[string]any)
				if parameter["name"] == "Idempotency-Key" && parameter["required"] == true && operation["x-trstctl-read-only"] == true {
					t.Errorf("%s %s mutation is incorrectly labeled read-only", method, path)
				}
			}
		}
	}
}
