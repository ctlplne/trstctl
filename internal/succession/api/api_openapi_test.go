// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	succapi "trstctl.com/trstctl/internal/succession/api"
)

// TestOpenAPI_Golden regenerates the PCAS OpenAPI 3.1 document from the route/schema
// metadata and asserts the checked-in openapi.pcas.json matches, so the published
// contract cannot drift. Run with UPDATE_GOLDEN=1 to refresh the file.
func TestOpenAPI_Golden(t *testing.T) {
	got, err := json.MarshalIndent(succapi.OpenAPISpec(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	const path = "openapi.pcas.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (create it with UPDATE_GOLDEN=1): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; regenerate with UPDATE_GOLDEN=1", path)
	}

	// Sanity: OpenAPI 3.1, the three PCAS paths, and Idempotency-Key on every mutation.
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi version = %v, want 3.1.0", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)
	for _, p := range []string{"/api/v1/pcas/successions", "/api/v1/pcas/chain", "/api/v1/pcas/acks"} {
		if _, ok := paths[p]; !ok {
			t.Fatalf("path %q missing from the PCAS OpenAPI document", p)
		}
	}
	checkpointRoute := paths["/api/v1/pcas/checkpoints"].(map[string]any)["get"].(map[string]any)
	response := checkpointRoute["responses"].(map[string]any)["200"].(map[string]any)
	content := response["content"].(map[string]any)["application/json"].(map[string]any)
	if got := content["schema"].(map[string]any)["$ref"]; got != "#/components/schemas/PCASCheckpoint" {
		t.Fatalf("checkpoint response schema = %v", got)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	federation := schemas["PCASFederationImportRequest"].(map[string]any)["properties"].(map[string]any)
	if got := federation["foreign_genesis"].(map[string]any)["type"]; got != "object" {
		t.Fatalf("federation genesis schema type = %v, want object record", got)
	}
	chain := federation["foreign_chain"].(map[string]any)["items"].(map[string]any)
	if got := chain["type"]; got != "object" {
		t.Fatalf("federation chain item schema type = %v, want object record", got)
	}
	checkpoint := schemas["PCASCheckpoint"].(map[string]any)["properties"].(map[string]any)
	if _, ok := checkpoint["signer_public_der"]; !ok {
		t.Fatal("checkpoint signer public key absent from published schema")
	}
	if got := checkpoint["checkpoint"].(map[string]any)["$ref"]; got != "#/components/schemas/PCASSignedEpochCheckpoint" {
		t.Fatalf("nested signed checkpoint schema = %v", got)
	}
	recoveryRequest := schemas["PCASRecoveryRequest"].(map[string]any)["properties"].(map[string]any)
	if got := recoveryRequest["authorization"].(map[string]any)["$ref"]; got != "#/components/schemas/PCASRecoveryAuthorization" {
		t.Fatalf("recovery authorization schema = %v, want structured signed artifact", got)
	}
	authorization := schemas["PCASRecoveryAuthorization"].(map[string]any)["properties"].(map[string]any)
	if got := authorization["Statement"].(map[string]any)["$ref"]; got != "#/components/schemas/PCASRecoveryStatement" {
		t.Fatalf("recovery statement schema = %v, want bound statement", got)
	}
	successor := schemas["PCASRecoverySuccessor"].(map[string]any)
	if _, ok := successor["properties"].(map[string]any)["tenant_id"]; !ok {
		t.Fatal("prepared successor readback does not publish its signed tenant binding")
	}
	for _, rt := range succapi.Routes(nil) {
		if !rt.Mutation {
			continue
		}
		item := paths[rt.Path].(map[string]any)
		op := item[lower(rt.Method)].(map[string]any)
		params, _ := op["parameters"].([]any)
		if !hasIdempotencyHeader(params) {
			t.Fatalf("mutation %s %s does not document the Idempotency-Key header", rt.Method, rt.Path)
		}
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func hasIdempotencyHeader(params []any) bool {
	for _, p := range params {
		m, _ := p.(map[string]any)
		if m["name"] == "Idempotency-Key" && m["in"] == "header" {
			return true
		}
	}
	return false
}
