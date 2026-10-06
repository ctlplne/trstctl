// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestKeyCompromiseRequiresBothIdentityAndHostAuthority(t *testing.T) {
	roles := []authz.Role{
		{Name: "identity-only", Permissions: []authz.Permission{authz.IdentitiesWrite}},
		{Name: "host-only", Permissions: []authz.Permission{authz.ConnectorsWrite}},
	}
	handler := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(roles...))
	for _, path := range []string{
		"/api/v1/identities/11111111-1111-1111-1111-111111111111/compromise/preview",
		"/api/v1/identities/11111111-1111-1111-1111-111111111111/compromise",
	} {
		for _, role := range []string{"identity-only", "host-only"} {
			t.Run(role+path, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"target_id":"22222222-2222-2222-2222-222222222222"}`))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-Tenant-ID", "33333333-3333-3333-3333-333333333333")
				request.Header.Set("X-Subject", "operator")
				request.Header.Set("X-Roles", role)
				request.Header.Set("Idempotency-Key", "rbac-review")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusForbidden {
					t.Fatalf("%s = %d, want 403: %s", path, response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestKeyCompromiseStatusRequiresBothReadAuthorities(t *testing.T) {
	roles := []authz.Role{
		{Name: "identity-reader", Permissions: []authz.Permission{authz.IdentitiesRead}},
		{Name: "host-reader", Permissions: []authz.Permission{authz.ConnectorsRead}},
	}
	handler := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(roles...))
	for _, role := range []string{"identity-reader", "host-reader"} {
		t.Run(role, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet,
				"/api/v1/identities/11111111-1111-1111-1111-111111111111/compromise?request_key=one", nil)
			request.Header.Set("X-Tenant-ID", "33333333-3333-3333-3333-333333333333")
			request.Header.Set("X-Subject", "operator")
			request.Header.Set("X-Roles", role)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status read = %d, want 403: %s", response.Code, response.Body.String())
			}
		})
	}
}
