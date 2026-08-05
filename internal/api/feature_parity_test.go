// SPDX-License-Identifier: MPL-2.0

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

func TestEveryOpenAPIOperationMapsToFeature(t *testing.T) {
	operations := openAPIOperationIDs(t, fetchSpec(t))
	mapped := map[string][]string{}
	for _, item := range loadFeatureParityCatalog(t).Items {
		for _, opID := range item.APISurface {
			opID = strings.TrimSpace(opID)
			if opID == "" {
				continue
			}
			mapped[opID] = append(mapped[opID], item.FeatureID)
		}
	}
	for opID := range operations {
		if len(mapped[opID]) == 0 {
			t.Errorf("OpenAPI operationId %q is served but not mapped to a feature catalog row", opID)
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
	// The discovery coverage surface raised this to 298; the ACME external
	// account binding operator surface (B4: list, disable, enable) raised it to
	// 301 and is mapped onto F5 in the same change; the agent job ledger's
	// operations surface (A1) raised it to 302 and is mapped onto F3; the AD CS
	// certificate template posture read (F1) raised it to 303 and is mapped
	// onto the discovery/posture feature row in the same change; the per-issuer
	// capability matrix (R2) raised it to 304 and is mapped onto the issuer
	// feature rows in the same change; the upstream authorization staleness
	// read (B7) raised it to 305 and is mapped onto the DNS-01 feature row,
	// because it answers "can this deployment still validate" for the same
	// provider configs that row already covers; D2's observed endpoint identity
	// raised it to 306 and is mapped onto F7, the deployment-connector row
	// whose delivery receipts it is the missing half of.
	// M2's crypto readiness raised it to 315 and is mapped onto the same graph
	// row as blast radius and reachability: it is the trust graph answering a
	// different question over the same edges — not who is reachable from a
	// node, but who depends on the crypto a node exhibits.
	// The count is a deliberate ratchet: every new operation must be mapped to
	// a feature-catalog row in the same change.
	if len(out) != 315 {
		t.Fatalf("OpenAPI operationIds = %d, want 315", len(out))
	}
	return out
}
