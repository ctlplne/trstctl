// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authmethod"
)

/* C-S2 (07-closeout plan, DA-02): GET /api/v1/secrets/auth-methods projects the
 * machine-auth methods the login exchange actually accepts — the same
 * composition authManager builds (builtin token method from AuthSecret + the
 * per-tenant config factory) — as an allow-listed, secret-free read. */

const (
	authMethodsTenantA = "11111111-1111-1111-1111-111111111111"
	authMethodsTenantB = "22222222-2222-2222-2222-222222222222"
)

func authMethodsHandler(t *testing.T) http.Handler {
	t.Helper()
	return api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithSecrets(api.SecretsBackend{
		AuthSecret: []byte("supersecret-hmac-material"),
		MachineAuthMethods: func(tenantID string) []authmethod.Method {
			if tenantID != authMethodsTenantA {
				return nil
			}
			return []authmethod.Method{
				authmethod.JWTMethod{
					NameValue:   "ci-jwt",
					Issuer:      "https://ci.example.test",
					Audience:    "trstctl",
					TenantID:    tenantID,
					TenantClaim: "tenant",
					Scopes:      []string{"secrets:read"},
				},
				authmethod.KubernetesSATMethod{
					Issuer:                 "https://kubernetes.default.svc",
					Audience:               "trstctl",
					TenantID:               tenantID,
					AllowedNamespaces:      map[string]bool{"payments": true},
					AllowedServiceAccounts: map[string]bool{"payments-bot": true},
					Scopes:                 []string{"secrets:read", "secrets:write"},
				},
			}
		},
	}))
}

func listAuthMethods(t *testing.T, handler http.Handler, tenantID string) (*httptest.ResponseRecorder, struct {
	Items []struct {
		Name           string   `json:"name"`
		Type           string   `json:"type"`
		Source         string   `json:"source"`
		Issuer         string   `json:"issuer"`
		Audience       string   `json:"audience"`
		Scopes         []string `json:"scopes"`
		JWKSConfigured bool     `json:"jwks_configured"`
	} `json:"items"`
}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/auth-methods", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-Subject", "operator-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var out struct {
		Items []struct {
			Name           string   `json:"name"`
			Type           string   `json:"type"`
			Source         string   `json:"source"`
			Issuer         string   `json:"issuer"`
			Audience       string   `json:"audience"`
			Scopes         []string `json:"scopes"`
			JWKSConfigured bool     `json:"jwks_configured"`
		} `json:"items"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode auth methods: %v; body=%s", err, rec.Body.String())
		}
	}
	return rec, out
}

func TestListMachineAuthMethodsProjectsConfiguredMethods(t *testing.T) {
	handler := authMethodsHandler(t)
	rec, got := listAuthMethods(t, handler, authMethodsTenantA)
	if rec.Code != http.StatusOK {
		t.Fatalf("list auth methods = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(got.Items) != 3 {
		t.Fatalf("items = %d, want 3 (builtin token + jwt + kubernetes); body=%s", len(got.Items), rec.Body.String())
	}
	// The builtin token method (from AuthSecret) leads, then config order.
	if got.Items[0].Type != "token" || got.Items[0].Source != "builtin" {
		t.Fatalf("first item = %+v, want builtin token method", got.Items[0])
	}
	byName := map[string]int{}
	for i, item := range got.Items {
		byName[item.Name] = i
	}
	jwtIdx, ok := byName["ci-jwt"]
	if !ok {
		t.Fatalf("configured jwt method missing: %+v", got.Items)
	}
	jwt := got.Items[jwtIdx]
	if jwt.Type != "jwt" || jwt.Source != "config" || jwt.Issuer != "https://ci.example.test" || jwt.Audience != "trstctl" {
		t.Fatalf("jwt projection = %+v", jwt)
	}
	if len(jwt.Scopes) != 1 || jwt.Scopes[0] != "secrets:read" {
		t.Fatalf("jwt scopes = %v", jwt.Scopes)
	}
	if _, ok := byName["kubernetes"]; !ok {
		t.Fatalf("kubernetes method missing: %+v", got.Items)
	}
}

func TestListMachineAuthMethodsNeverSerializesSecretMaterial(t *testing.T) {
	handler := authMethodsHandler(t)
	rec, _ := listAuthMethods(t, handler, authMethodsTenantA)
	if rec.Code != http.StatusOK {
		t.Fatalf("list auth methods = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, needle := range []string{"supersecret", "c3VwZXJzZWNyZXQ", "Secret", "jwks\":", "JWKS"} {
		if strings.Contains(body, needle) {
			t.Fatalf("response leaks secret-shaped material (%q): %s", needle, body)
		}
	}
}

func TestListMachineAuthMethodsIsTenantScoped(t *testing.T) {
	handler := authMethodsHandler(t)
	rec, got := listAuthMethods(t, handler, authMethodsTenantB)
	if rec.Code != http.StatusOK {
		t.Fatalf("list auth methods = %d, want 200", rec.Code)
	}
	// Tenant B has no configured methods — only the builtin token exchange.
	if len(got.Items) != 1 || got.Items[0].Type != "token" {
		t.Fatalf("tenant-b items = %+v, want builtin token only", got.Items)
	}
	if strings.Contains(rec.Body.String(), "ci-jwt") {
		t.Fatalf("tenant-b response leaks tenant-a method config: %s", rec.Body.String())
	}
}

func TestListMachineAuthMethodsRequiresSecretsRead(t *testing.T) {
	handler := authMethodsHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/auth-methods", nil)
	req.Header.Set("X-Tenant-ID", authMethodsTenantA)
	// No roles: the principal has no permissions, so the read must be refused.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("list auth methods without secrets:read = %d, want a 4xx refusal; body=%s", rec.Code, rec.Body.String())
	}
}

func TestListMachineAuthMethodsWhenSecretsDisabled(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/auth-methods", nil)
	req.Header.Set("X-Tenant-ID", authMethodsTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list auth methods with secrets disabled = %d, want 404 problem; body=%s", rec.Code, rec.Body.String())
	}
}
