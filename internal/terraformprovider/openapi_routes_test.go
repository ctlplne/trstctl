package terraformprovider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTerraformProviderRoutesStayGeneratedFromOpenAPI(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "clients", "sdk", "openapi.json"))
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	found := map[string]string{}
	for path, methods := range doc.Paths {
		for method, op := range methods {
			if op.OperationID != "" {
				found[op.OperationID] = method + " " + path
			}
		}
	}
	want := map[string]string{
		"createProfile":     "post " + routeCreateProfilePath,
		"getProfileVersion": "get " + routeGetProfileVersionPath,
		"issuePKISecret":    "post " + routeIssuePKISecretPath,
		"createSecret":      "post " + routeCreateSecretPath,
		"getSecret":         "get " + routeGetSecretPath,
		"rotateSecret":      "put " + routeRotateSecretPath,
		"deleteSecret":      "delete " + routeDeleteSecretPath,
	}
	for opID, route := range want {
		if found[opID] != route {
			t.Errorf("%s route = %q, want %q", opID, found[opID], route)
		}
	}
	if len(terraformProviderOperationIDs) != len(want) {
		t.Fatalf("generated operation id count = %d, want %d", len(terraformProviderOperationIDs), len(want))
	}
}
