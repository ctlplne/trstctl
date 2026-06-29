package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestRemediationSurface404sWhenNotAttached(t *testing.T) {
	h := New(nil, nil, nil)
	probes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/incidents/executions", `{"identity_id":"id-1"}`},
		{http.MethodGet, "/api/v1/incidents/executions", ""},
		{http.MethodGet, "/api/v1/incidents/executions/exec-1", ""},
		{http.MethodGet, "/api/v1/remediation/playbooks", ""},
		{http.MethodPost, "/api/v1/remediation/playbooks/nhi-right-size/runs", `{"inventory_id":"identity/id-1"}`},
		{http.MethodGet, "/api/v1/remediation/playbook-runs", ""},
		{http.MethodGet, "/api/v1/remediation/playbook-runs/run-1", ""},
		{http.MethodPost, "/api/v1/incidents/response-integrations/dispatch", `{"title":"x","destinations":[{"provider":"slack"}]}`},
		{http.MethodPost, "/api/v1/pqc/migrations", `{"asset_ids":["asset-1"],"target_algorithm":"ML-DSA-65"}`},
		{http.MethodPost, "/api/v1/pqc/migrations/run-1/rollback", `{"asset_ids":["asset-1"]}`},
	}
	for _, probe := range probes {
		req := httptest.NewRequest(probe.method, probe.path, strings.NewReader(probe.body))
		if probe.method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "remediation-unlicensed")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s without remediation attach = %d, want 404; body=%s", probe.method, probe.path, rec.Code, rec.Body.String())
		}
	}
}

func TestRemediationSurfaceKeepsRBACWhenAttached(t *testing.T) {
	reader := authz.Role{Name: "incident-reader", Permissions: []authz.Permission{authz.IncidentsRead}}
	h := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(reader), WithRemediation())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/executions", strings.NewReader(`{"identity_id":"id-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "remediation-rbac")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "viewer")
	req.Header.Set("X-Roles", "incident-reader")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attached incident execution with read-only role = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/remediation/playbooks/nhi-right-size/runs", strings.NewReader(`{"inventory_id":"identity/id-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "playbook-rbac")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "viewer")
	req.Header.Set("X-Roles", "incident-reader")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attached playbook run with read-only role = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/incidents/response-integrations/dispatch", strings.NewReader(`{"title":"x","destinations":[{"provider":"slack"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "response-integrations-rbac")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "viewer")
	req.Header.Set("X-Roles", "incident-reader")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attached response integration dispatch with read-only role = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/pqc/migrations", strings.NewReader(`{"asset_ids":["asset-1"],"target_algorithm":"ML-DSA-65"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "pqc-rbac")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "viewer")
	req.Header.Set("X-Roles", "incident-reader")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attached PQC migration with no certs:issue role = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}
