// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
)

func cr824Policy(t *testing.T, module string) *policy.ABACEngine {
	t.Helper()
	engine, err := policy.NewABAC(policy.ABACConfig{Module: module})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func cr824Request(t *testing.T, h http.Handler, method, path, project string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	req.Header.Set("X-Tenant-ID", "cr824-tenant")
	req.Header.Set("X-Subject", "cr824-operator")
	req.Header.Set("X-Roles", "operator")
	req.Header.Set("Idempotency-Key", "cr824-"+method+"-"+project)
	if project != "" {
		req.Header.Set("X-Project", project)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCR824ProjectDenyUsesTargetSlugForEveryHeader(t *testing.T) {
	engine := cr824Policy(t, `package trstctl.abac
default deny := false
default reason := ""
deny if {
	input.permission == "secrets:read"
	input.resource.project == "payments"
}

reason := "payments closed" if {
	input.permission == "secrets:read"
	input.resource.project == "payments"
}
`)
	h := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithABACDenyOverlay(engine, nil, nil))
	for _, header := range []string{"", "staging", "payments"} {
		got := cr824Request(t, h, http.MethodGet, "/api/v1/secrets/projects/payments", header)
		if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "denied by ABAC") {
			t.Errorf("target payments, X-Project=%q: HTTP %d %s; want ABAC denial", header, got.Code, got.Body.String())
		}
	}
}

func TestCR824CreateProjectUsesValidatedSlug(t *testing.T) {
	engine := cr824Policy(t, `package trstctl.abac
default deny := false
default reason := ""
deny if {
	input.permission == "access:write"
	input.resource.project == "payments"
}
reason := "payments closed" if { deny }
`)
	h := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithABACDenyOverlay(engine, nil, nil))
	for _, header := range []string{"", "staging"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/projects", strings.NewReader(`{"slug":"payments"}`))
		req.Header.Set("X-Tenant-ID", "cr824-tenant")
		req.Header.Set("X-Subject", "cr824-operator")
		req.Header.Set("X-Roles", "admin")
		req.Header.Set("Idempotency-Key", "cr824-create-"+header)
		if header != "" {
			req.Header.Set("X-Project", header)
		}
		got := httptest.NewRecorder()
		h.ServeHTTP(got, req)
		if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "payments closed") {
			t.Errorf("create payments, X-Project=%q: HTTP %d %s; want ABAC denial", header, got.Code, got.Body.String())
		}
	}
}

func TestCR824HeaderCannotSatisfyUnscopedBreakglassRule(t *testing.T) {
	engine := cr824Policy(t, `package trstctl.abac
default deny := false
default reason := ""
deny if {
	startswith(input.resource["request.path"], "/api/v1/breakglass/")
	not input.resource.project == "platform"
}
reason := "no verified platform project" if {
	startswith(input.resource["request.path"], "/api/v1/breakglass/")
	not input.resource.project == "platform"
}
`)
	h := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithABACDenyOverlay(engine, nil, nil))
	for _, header := range []string{"", "platform"} {
		got := cr824Request(t, h, http.MethodGet, "/api/v1/breakglass/issues", header)
		if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "denied by ABAC") {
			t.Errorf("unscoped breakglass, X-Project=%q: HTTP %d %s; want ABAC denial", header, got.Code, got.Body.String())
		}
	}
}

func TestCR824ProjectScopedGrantCannotUseHeaderOnUnscopedRoute(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	principal := authz.Principal{TenantID: "cr824-tenant", Subject: "scoped", Grants: []authz.Grant{{
		Role:  authz.Role{Name: "reader", Permissions: []authz.Permission{authz.SecretsRead}},
		Scope: authz.Scope{TenantID: "cr824-tenant", Project: "payments"},
	}}}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/store", nil)
	r.Header.Set("X-Project", "payments")
	target, err := a.requestTargetScope(principal, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if target.Project != "" || principal.Can(authz.SecretsRead, target) {
		t.Fatalf("unscoped route acquired project grant from header: %#v", target)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/secrets/projects/payments", nil)
	r.SetPathValue("project", "payments")
	target, err = a.requestTargetScope(principal, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if target.Project != "payments" || !principal.Can(authz.SecretsRead, target) {
		t.Fatalf("project route lost target project grant: %#v", target)
	}
}

func TestCR824VaultABACIgnoresProjectHeaderWithoutBackingProject(t *testing.T) {
	engine := cr824Policy(t, `package trstctl.abac
default deny := false
default reason := ""
deny if {
	input.permission == "secrets:read"
	not input.resource.project
}
reason := "no verified project" if { deny }
`)
	h := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithABACDenyOverlay(engine, nil, nil))
	for _, header := range []string{"", "payments"} {
		got := cr824Request(t, h, http.MethodGet, "/v1/secret/data/payments/prod/key", header)
		if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "no verified project") {
			t.Errorf("Vault KV, X-Project=%q: HTTP %d %s; want ABAC denial", header, got.Code, got.Body.String())
		}
	}
}
