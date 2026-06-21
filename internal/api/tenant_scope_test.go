package api

import (
	"context"
	"net/http"
	"net/http/httptest"
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
