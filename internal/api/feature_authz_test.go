// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/featureparity"
)

func TestFeatureAuthzManifestEnumeratesAPIRoutes(t *testing.T) {
	routes := api.New(nil, nil, nil).Routes()
	var manifestInput []featureparity.APIRouteAuthz
	for _, rt := range routes {
		if rt.OperationID == "" {
			t.Errorf("%s %s has no operationId in the authz route registry", rt.Method, rt.Path)
		}
		if rt.Permission != "" && rt.PublicRationale != "" {
			t.Errorf("%s %s declares both permission %q and public rationale %q", rt.Method, rt.Path, rt.Permission, rt.PublicRationale)
		}
		if rt.Permission == "" && rt.PublicRationale == "" {
			t.Errorf("%s %s has no permission or explicit public rationale", rt.Method, rt.Path)
		}
		manifestInput = append(manifestInput, featureparity.APIRouteAuthz{
			OperationID:     rt.OperationID,
			Method:          rt.Method,
			Path:            rt.Path,
			Permission:      string(rt.Permission),
			PublicRationale: rt.PublicRationale,
			OpenAPISecurity: rt.Permission != "",
		})
	}

	catalog, err := featureparity.Load()
	if err != nil {
		t.Fatalf("load feature catalog: %v", err)
	}
	entries, missing := featureparity.BuildAPIFeatureAuthzManifest(catalog, manifestInput)
	if len(missing) > 0 {
		t.Fatalf("feature authz manifest has missing API bindings:\n%s", strings.Join(missing, "\n"))
	}
	if len(entries) == 0 {
		t.Fatal("feature authz manifest has no API entries")
	}
	for _, e := range entries {
		if e.Permission == "" && e.PublicRationale == "" {
			t.Errorf("%s/%s has neither permission nor public rationale", e.FeatureID, e.OperationID)
		}
		if e.Permission != "" && !e.OpenAPISecurity {
			t.Errorf("%s/%s is permission-guarded by %q but not marked as OpenAPI-secured", e.FeatureID, e.OperationID, e.Permission)
		}
		if e.DefaultDenyTest != featureparity.APIFeatureAuthzTestRef {
			t.Errorf("%s/%s default-deny test = %q, want %q", e.FeatureID, e.OperationID, e.DefaultDenyTest, featureparity.APIFeatureAuthzTestRef)
		}
	}
}

func TestOpenAPISecurityMatchesRoutePermissions(t *testing.T) {
	doc := fetchSpec(t)
	components := doc["components"].(map[string]any)
	securitySchemes, ok := components["securitySchemes"].(map[string]any)
	if !ok || securitySchemes["BearerAuth"] == nil {
		t.Fatalf("OpenAPI components.securitySchemes.BearerAuth is missing")
	}
	paths := doc["paths"].(map[string]any)

	for _, rt := range api.New(nil, nil, nil).Routes() {
		if rt.Path == "/api/v1/openapi.json" {
			continue
		}
		pathItem, ok := paths[rt.Path].(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI path %s is missing", rt.Path)
		}
		op, ok := pathItem[strings.ToLower(rt.Method)].(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI operation %s %s is missing", rt.Method, rt.Path)
		}
		if rt.Permission == "" {
			if _, ok := op["security"]; ok {
				t.Errorf("%s %s is public but declares OpenAPI security", rt.Method, rt.Path)
			}
			if got := op["x-trstctl-public-rationale"]; got != rt.PublicRationale {
				t.Errorf("%s %s public rationale = %v, want %q", rt.Method, rt.Path, got, rt.PublicRationale)
			}
			continue
		}
		if got := op["x-trstctl-permission"]; got != string(rt.Permission) {
			t.Errorf("%s %s OpenAPI permission = %v, want %q", rt.Method, rt.Path, got, rt.Permission)
		}
		if !hasBearerSecurity(op) {
			t.Errorf("%s %s requires %q but OpenAPI has no BearerAuth security requirement", rt.Method, rt.Path, rt.Permission)
		}
	}
}

func hasBearerSecurity(op map[string]any) bool {
	raw, ok := op["security"].([]any)
	if !ok || len(raw) == 0 {
		return false
	}
	for _, entry := range raw {
		req, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := req["BearerAuth"]; ok {
			return true
		}
	}
	return false
}
