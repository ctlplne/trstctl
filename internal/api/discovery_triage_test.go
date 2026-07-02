package api

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestDiscoveryTriageRoutesAreGuardedIdempotentMutations(t *testing.T) {
	routes := New(nil, nil, nil).Routes()
	claim := findRoute(routes, http.MethodPost, "/api/v1/discovery/findings/{id}/claim")
	dismiss := findRoute(routes, http.MethodPost, "/api/v1/discovery/findings/{id}/dismiss")
	for name, rt := range map[string]Route{"claim": claim, "dismiss": dismiss} {
		if rt.OperationID == "" {
			t.Fatalf("%s route missing", name)
		}
		if !rt.Mutation {
			t.Fatalf("%s route is not marked as a mutation; the idempotency linter will not protect it", name)
		}
		if rt.Permission != authz.DiscoveryWrite {
			t.Fatalf("%s route permission = %q, want %q", name, rt.Permission, authz.DiscoveryWrite)
		}
	}
	if claim.OperationID != "claimDiscoveryFinding" {
		t.Fatalf("claim operationId = %q, want claimDiscoveryFinding", claim.OperationID)
	}
	if dismiss.OperationID != "dismissDiscoveryFinding" {
		t.Fatalf("dismiss operationId = %q, want dismissDiscoveryFinding", dismiss.OperationID)
	}
}

func TestCTMonitoringRoutesAreDedicatedServedSurface(t *testing.T) {
	routes := New(nil, nil, nil).Routes()
	get := findRoute(routes, http.MethodGet, "/api/v1/discovery/ct-monitoring")
	update := findRoute(routes, http.MethodPut, "/api/v1/discovery/ct-monitoring")

	if get.OperationID != "getCTMonitoring" {
		t.Fatalf("GET CT monitoring operationId = %q, want getCTMonitoring", get.OperationID)
	}
	if get.Mutation {
		t.Fatal("GET CT monitoring route must be read-only")
	}
	if get.Permission != authz.DiscoveryRead {
		t.Fatalf("GET CT monitoring permission = %q, want %q", get.Permission, authz.DiscoveryRead)
	}
	if update.OperationID != "updateCTMonitoring" {
		t.Fatalf("PUT CT monitoring operationId = %q, want updateCTMonitoring", update.OperationID)
	}
	if !update.Mutation {
		t.Fatal("PUT CT monitoring route must be marked as a mutation for idempotency enforcement")
	}
	if update.Permission != authz.DiscoveryWrite {
		t.Fatalf("PUT CT monitoring permission = %q, want %q", update.Permission, authz.DiscoveryWrite)
	}
}

func TestDriftRemediationRoutesAreDedicatedServedSurface(t *testing.T) {
	routes := New(nil, nil, nil).Routes()
	get := findRoute(routes, http.MethodGet, "/api/v1/discovery/drift-remediation")
	decide := findRoute(routes, http.MethodPost, "/api/v1/discovery/drift-remediation/{id}/decision")

	if get.OperationID != "getDriftRemediation" {
		t.Fatalf("GET drift remediation operationId = %q, want getDriftRemediation", get.OperationID)
	}
	if get.Mutation {
		t.Fatal("GET drift remediation route must be read-only")
	}
	if get.Permission != authz.DiscoveryRead {
		t.Fatalf("GET drift remediation permission = %q, want %q", get.Permission, authz.DiscoveryRead)
	}
	if decide.OperationID != "decideDriftRemediation" {
		t.Fatalf("POST drift remediation operationId = %q, want decideDriftRemediation", decide.OperationID)
	}
	if !decide.Mutation {
		t.Fatal("POST drift remediation route must be marked as a mutation for idempotency enforcement")
	}
	if decide.Permission != authz.DiscoveryWrite {
		t.Fatalf("POST drift remediation permission = %q, want %q", decide.Permission, authz.DiscoveryWrite)
	}
}

func findRoute(routes []Route, method, path string) Route {
	for _, rt := range routes {
		if rt.Method == method && rt.Path == path {
			return rt
		}
	}
	return Route{}
}
