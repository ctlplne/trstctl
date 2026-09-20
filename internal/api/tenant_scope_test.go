// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestTenantResolverUsesPrincipalOverHeader(t *testing.T) {
	const (
		principalTenant = "11111111-1111-1111-1111-111111111111"
		headerTenant    = "22222222-2222-2222-2222-222222222222"
	)
	api := New(nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req.Header.Set("X-Tenant-ID", headerTenant)
	req = req.WithContext(context.WithValue(req.Context(), principalCtxKey, authz.Principal{TenantID: principalTenant}))

	got, ok := api.tenant(req)
	if !ok || got != principalTenant {
		t.Fatalf("tenant() = %q, %v; want authenticated principal tenant %q, true", got, ok, principalTenant)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req.Header.Set("X-Tenant-ID", headerTenant)
	req = req.WithContext(context.WithValue(req.Context(), principalCtxKey, authz.Principal{}))

	got, ok = api.tenant(req)
	if ok || got != "" {
		t.Fatalf("tenant() with empty authenticated principal = %q, %v; want fail-closed without header fallback", got, ok)
	}
}

func TestGuardRejectsExplicitTenantHeaderMismatch(t *testing.T) {
	const (
		principalTenant = "11111111-1111-1111-1111-111111111111"
		otherTenant     = "22222222-2222-2222-2222-222222222222"
	)
	role := authz.Role{Name: "owner-reader", Permissions: []authz.Permission{authz.OwnersRead}}
	principal := authz.Principal{
		TenantID: principalTenant,
		Subject:  "api-automation",
		Grants:   []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: principalTenant}}},
	}
	api := New(nil, nil, nil, WithRoles(role), WithPrincipalResolver(func(*http.Request) (authz.Principal, error) {
		return principal, nil
	}))

	for _, tc := range []struct {
		name       string
		headers    []string
		wantStatus int
		wantRun    bool
	}{
		{name: "absent header uses credential tenant", wantStatus: http.StatusNoContent, wantRun: true},
		{name: "matching header confirms credential tenant", headers: []string{principalTenant}, wantStatus: http.StatusNoContent, wantRun: true},
		{name: "mismatched header fails closed", headers: []string{otherTenant}, wantStatus: http.StatusForbidden, wantRun: false},
		{name: "duplicate conflicting header fails closed", headers: []string{principalTenant, otherTenant}, wantStatus: http.StatusForbidden, wantRun: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlerRan := false
			handler := api.guard(authz.OwnersRead, nil, func(w http.ResponseWriter, _ *http.Request) {
				handlerRan = true
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
			for _, header := range tc.headers {
				req.Header.Add("X-Tenant-ID", header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("guard status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if handlerRan != tc.wantRun {
				t.Fatalf("handler ran = %v, want %v", handlerRan, tc.wantRun)
			}
			if !tc.wantRun {
				if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
					t.Errorf("Content-Type = %q, want application/problem+json", got)
				}
				if !strings.Contains(rec.Body.String(), "tenant") {
					t.Errorf("problem detail does not explain the tenant mismatch: %s", rec.Body.String())
				}
			}
		})
	}
}

func TestVaultAuthRejectsExplicitTenantHeaderMismatch(t *testing.T) {
	const (
		principalTenant = "11111111-1111-1111-1111-111111111111"
		otherTenant     = "22222222-2222-2222-2222-222222222222"
	)
	role := authz.Role{Name: "secret-reader", Permissions: []authz.Permission{authz.SecretsRead}}
	principal := authz.Principal{
		TenantID: principalTenant,
		Subject:  "vault-automation",
		Grants:   []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: principalTenant}}},
	}
	api := New(nil, nil, nil, WithRoles(role), WithPrincipalResolver(func(*http.Request) (authz.Principal, error) {
		return principal, nil
	}))
	handlerRan := false
	handler := api.vaultAuth(authz.SecretsRead, func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/example", nil)
	req.Header.Set("X-Tenant-ID", otherTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("vault guard status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if handlerRan {
		t.Fatal("mismatched Vault request reached the protected handler")
	}
}
