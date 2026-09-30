// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestProfileScopedIssueRouteUsesRequestProfile(t *testing.T) {
	role := authz.Role{Name: "profile-issuer", Permissions: []authz.Permission{authz.CertsIssue}}
	h := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(role))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/external-cas/issuer-any/issue",
		strings.NewReader(`{"profile_name":"tls-dev","csr_pem":"bad"}`))
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "issuer")
	req.Header.Set("X-Roles", "profile-issuer")
	req.Header.Set("X-Role-Profile", "tls-prod")
	req.Header.Set("Idempotency-Key", "issue-dev")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("profile-scoped issue with wrong profile = %d, want 403: %s", rec.Code, rec.Body.String())
	}

	a := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(role))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/external-cas/issuer-any/issue",
		strings.NewReader(`{"profile_name":"tls-prod","csr_pem":"bad"}`))
	req.SetPathValue("id", "issuer-any")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "issuer")
	req.Header.Set("X-Roles", "profile-issuer")
	req.Header.Set("X-Role-Profile", "tls-prod")
	bodyReachedHandler := false
	handler := a.guard(authz.CertsIssue, combineRouteScopes(scopeIssuerPath("id"), scopeProfileJSON("profile_name")), func(w http.ResponseWriter, r *http.Request) {
		bodyReachedHandler = true
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body after scoped guard: %v", err)
		}
		if !strings.Contains(string(body), `"profile_name":"tls-prod"`) {
			t.Fatalf("guard did not preserve request body: %s", string(body))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("profile-scoped issue with matching profile = %d, want guarded handler to run: %s", rec.Code, rec.Body.String())
	}
	if !bodyReachedHandler {
		t.Fatal("profile-scoped issue with matching profile never reached handler")
	}
}

func TestIssuerScopedGuardUsesPathIssuer(t *testing.T) {
	role := authz.Role{Name: "issuer-manager", Permissions: []authz.Permission{authz.IssuersWrite}}
	a := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(role))
	handlerRan := false
	handler := a.guard(authz.IssuersWrite, scopeIssuerPath("id"), func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/authorities/issuer-dev/issue", nil)
	req.SetPathValue("id", "issuer-dev")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "issuer-admin")
	req.Header.Set("X-Roles", "issuer-manager")
	req.Header.Set("X-Role-Issuer", "issuer-prod")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("issuer-scoped manage with wrong issuer = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if handlerRan {
		t.Fatal("issuer-scoped manage with wrong issuer reached handler")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/ca/authorities/issuer-prod/issue", nil)
	req.SetPathValue("id", "issuer-prod")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Subject", "issuer-admin")
	req.Header.Set("X-Roles", "issuer-manager")
	req.Header.Set("X-Role-Issuer", "issuer-prod")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("issuer-scoped manage with matching issuer = %d, want guarded handler to run: %s", rec.Code, rec.Body.String())
	}
	if !handlerRan {
		t.Fatal("issuer-scoped manage with matching issuer never reached handler")
	}
}

func TestIssuerScopedRequestUsesSelectedBodyIssuer(t *testing.T) {
	role := authz.Role{Name: "scoped-requester", Permissions: []authz.Permission{authz.CertsRequest}}
	a := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(role))
	reached := false
	handler := a.guard(authz.CertsRequest, scopeIssuanceRequestIssuer, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), `"id":"allowed-ca"`) {
			t.Fatalf("request body was not preserved after issuer scope check: %v %s", err, body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	call := func(issuer string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/issuance-requests/preview",
			strings.NewReader(`{"issuer":{"source":"external","id":"`+issuer+`"}}`))
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("X-Subject", "requester")
		req.Header.Set("X-Roles", "scoped-requester")
		req.Header.Set("X-Role-Issuer", "allowed-ca")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call("other-ca"); got != http.StatusForbidden || reached {
		t.Fatalf("request for unauthorized CA reached handler: status=%d reached=%v", got, reached)
	}
	if got := call("allowed-ca"); got != http.StatusNoContent || !reached {
		t.Fatalf("request for allowed CA refused: status=%d reached=%v", got, reached)
	}
}

func TestCARotationRequiresSuccessorIssuerScope(t *testing.T) {
	role := authz.Role{Name: "issuer-manager", Permissions: []authz.Permission{authz.IssuersWrite}}
	predecessorOnly := authz.Principal{
		TenantID: "tenant-1",
		Subject:  "issuer-admin",
		Grants:   []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: "tenant-1", Issuer: "issuer-old"}}},
	}
	ctx := context.WithValue(context.Background(), principalCtxKey, predecessorOnly)
	if err := authorizeCARotationSuccessor(ctx, "tenant-1", "issuer-new"); err == nil {
		t.Fatal("predecessor-scoped rotation principal authorized an unauthorized successor")
	}

	tenantWide := authz.Principal{
		TenantID: "tenant-1",
		Subject:  "issuer-admin",
		Grants:   []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: "tenant-1"}}},
	}
	ctx = context.WithValue(context.Background(), principalCtxKey, tenantWide)
	if err := authorizeCARotationSuccessor(ctx, "tenant-1", "issuer-new"); err != nil {
		t.Fatalf("tenant-wide issuer manager should authorize successor rotation: %v", err)
	}
}
