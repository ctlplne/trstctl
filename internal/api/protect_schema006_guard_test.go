// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// SCHEMA-006 (16-SCHEMA) PROTECT regression guard.
//
// Confirmed strength: the REST API is versioned under /api/v1, generated from a route
// registry (so the served surface and the published OpenAPI contract cannot drift),
// and guarded against blanks. Anchor: internal/api/api.go (the route registry) +
// internal/api/openapi.go (buildSpec, built once from that registry).
//
// This is a BEHAVIORAL test: api.New tolerates nil dependencies "when only the spec is
// needed" (per its doc comment), so we build a real API with nil store/idem/orch and
// exercise the actual exported Routes() and Spec(). No Postgres, no NATS, no network.
// It asserts the version prefix on every route, that the registry is non-empty, that
// the in-memory OpenAPI document was built from the registry, and the no-blank
// property (every route has a path + operation id; every documented operation has an
// operationId and at least one response). If a future route escapes /api/v1, or the
// spec stops being generated from the registry, or a blank slips in, this guard goes
// RED.
func TestProtectSCHEMA006_RoutesVersionedAndSpecGenerated(t *testing.T) {
	a := api.New(nil, nil, nil)

	routes := a.Routes()
	if len(routes) == 0 {
		t.Fatal("SCHEMA-006: the route registry is empty; the served REST surface is generated from it and must be non-empty")
	}

	// Every served route is under /api/v1 (the single versioned prefix) and carries a
	// non-blank operation id — the no-blank property.
	for _, r := range routes {
		if !strings.HasPrefix(r.Path, "/api/v1") {
			t.Errorf("SCHEMA-006: route %s %s is not under the /api/v1 version prefix; the API must stay single-versioned", r.Method, r.Path)
		}
		if r.Method == "" {
			t.Errorf("SCHEMA-006: route for path %q has a blank HTTP method", r.Path)
		}
		if r.OperationID == "" {
			t.Errorf("SCHEMA-006: route %s %s has a blank operationId; generated clients need a stable id per route", r.Method, r.Path)
		}
	}

	// The OpenAPI document is generated once from the registry and must be consistent
	// with what is served.
	spec := a.Spec()
	if spec == nil {
		t.Fatal("SCHEMA-006: Spec() returned nil; the OpenAPI document is no longer built from the route registry")
	}
	if spec.OpenAPI == "" {
		t.Error("SCHEMA-006: OpenAPI document has a blank openapi version field")
	}
	if spec.Info.Version != "v1" {
		t.Errorf("SCHEMA-006: OpenAPI Info.Version = %q, want \"v1\" (the API version is fixed at v1)", spec.Info.Version)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("SCHEMA-006: OpenAPI document has zero paths; the spec builder did not run over the route registry")
	}

	// No-blank + version consistency at the document level: every documented path is
	// under /api/v1, and every operation has an operationId and at least one response.
	for path, item := range spec.Paths {
		if !strings.HasPrefix(path, "/api/v1") {
			t.Errorf("SCHEMA-006: OpenAPI path %q is not under /api/v1", path)
		}
		if len(item) == 0 {
			t.Errorf("SCHEMA-006: OpenAPI path %q has no operations (blank path item)", path)
		}
		for method, op := range item {
			if op == nil {
				t.Errorf("SCHEMA-006: OpenAPI path %q method %q has a nil operation", path, method)
				continue
			}
			if op.OperationID == "" {
				t.Errorf("SCHEMA-006: OpenAPI operation at %q %q has a blank operationId", path, method)
			}
			if len(op.Responses) == 0 {
				t.Errorf("SCHEMA-006: OpenAPI operation at %q %q declares no responses (blank contract)", path, method)
			}
		}
	}

	// The registry-driven document must cover every guarded served route (modulo the
	// spec endpoint itself, which buildSpec intentionally omits). This is the property
	// that keeps the served surface and the published contract from drifting.
	for _, r := range routes {
		if r.OperationID == "getOpenAPISpec" {
			continue // the spec route is deliberately not documented in itself
		}
		item, ok := spec.Paths[r.Path]
		if !ok {
			t.Errorf("SCHEMA-006: served route %s %s is not present in the generated OpenAPI document; the registry and the spec have drifted", r.Method, r.Path)
			continue
		}
		if _, ok := item[strings.ToLower(r.Method)]; !ok {
			t.Errorf("SCHEMA-006: served route method %s missing for path %s in the OpenAPI document", r.Method, r.Path)
		}
	}
}
