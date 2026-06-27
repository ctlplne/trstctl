package api_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/featureparity"
)

func TestFeatureParityMapsCatalogRowsToOpenAPIOperations(t *testing.T) {
	operations := openAPIOperationIDs(t, fetchSpec(t))

	for _, item := range loadFeatureParityCatalog(t).Items {
		if len(item.APISurface) == 0 && strings.TrimSpace(item.APINA) == "" {
			t.Errorf("%s (%s) has no api_surface operations and no api_na reason", item.FeatureID, item.Feature)
		}
		if len(item.APISurface) > 0 && strings.TrimSpace(item.APINA) != "" {
			t.Errorf("%s (%s) declares both api_surface and api_na", item.FeatureID, item.Feature)
		}
		for _, opID := range item.APISurface {
			if strings.TrimSpace(opID) == "" {
				t.Errorf("%s (%s) has a blank api_surface operation", item.FeatureID, item.Feature)
				continue
			}
			if !operations[opID] {
				t.Errorf("%s (%s) references missing OpenAPI operationId %q", item.FeatureID, item.Feature, opID)
			}
		}
	}
}

func loadFeatureParityCatalog(t *testing.T) featureparity.Catalog {
	t.Helper()
	catalog, err := featureparity.Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	return catalog
}

func openAPIOperationIDs(t *testing.T, doc map[string]any) map[string]bool {
	t.Helper()
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI document has no paths object")
	}
	out := map[string]bool{}
	for path, rawPathItem := range paths {
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI path %s is not an object", path)
		}
		for method, rawOp := range pathItem {
			op, ok := rawOp.(map[string]any)
			if !ok {
				t.Fatalf("OpenAPI %s %s is not an operation object", strings.ToUpper(method), path)
			}
			opID, ok := op["operationId"].(string)
			if !ok || strings.TrimSpace(opID) == "" {
				t.Fatalf("OpenAPI %s %s has no operationId", strings.ToUpper(method), path)
			}
			if out[opID] {
				t.Fatalf("OpenAPI operationId %q is duplicated", opID)
			}
			out[opID] = true
		}
	}
	if len(out) != 131 {
		t.Fatalf("OpenAPI operationIds = %d, want 131", len(out))
	}
	return out
}
