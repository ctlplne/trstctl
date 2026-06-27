package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

// stubManagedKeys is a minimal ManagedKeyService used to prove the served route is
// wired and reaches the service. The lifecycle itself is covered end to end against
// a fake KMS in ee/managedkeys; here we only assert HTTP wiring/fail-closed.
type stubManagedKeys struct {
	generated bool
}

func (s *stubManagedKeys) Generate(_ context.Context, tenantID string, alg crypto.Algorithm, _ string) (api.ManagedKey, error) {
	s.generated = true
	return api.ManagedKey{KeyID: "fake-kms-key-0001", Algorithm: alg, Version: 1, State: "active"}, nil
}
func (s *stubManagedKeys) Rotate(context.Context, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}
func (s *stubManagedKeys) Revoke(context.Context, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}
func (s *stubManagedKeys) Zeroize(context.Context, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}

// TestManagedKeysServedReflectsWiring proves the CRYPTO-005 wiring assertion: the
// served surface reports enabled only when WithManagedKeys is given.
func TestManagedKeysServedReflectsWiring(t *testing.T) {
	if api.New(nil, nil, nil).ManagedKeysServed() {
		t.Fatal("ManagedKeysServed() true with no backend wired")
	}
	if !api.New(nil, nil, nil, api.WithManagedKeys(&stubManagedKeys{})).ManagedKeysServed() {
		t.Fatal("ManagedKeysServed() false after WithManagedKeys")
	}
}

// TestManagedKeyRouteIsRegistered proves all four managed-key operations are in the
// served route registry (and therefore the OpenAPI surface and the CLI parity set).
func TestManagedKeyRouteIsRegistered(t *testing.T) {
	want := map[string]bool{
		"POST /api/v1/managed-keys":         false,
		"POST /api/v1/managed-keys/rotate":  false,
		"POST /api/v1/managed-keys/revoke":  false,
		"POST /api/v1/managed-keys/zeroize": false,
	}
	for _, rt := range api.New(nil, nil, nil).Routes() {
		key := rt.Method + " " + rt.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("served route %q is not registered", key)
		}
	}
}

// TestManagedKeyRouteIsHiddenWhenUnlicensed proves an authenticated request to the
// generate route returns 404 when the licensed BYOK surface is not wired. Community
// must not expose a dormant mutating managed-key route.
func TestManagedKeyRouteIsHiddenWhenUnlicensed(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/managed-keys", strings.NewReader(`{"algorithm":"ECDSA-P256"}`))
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("Idempotency-Key", "k1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unlicensed managed-keys status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestManagedKeyRouteRejectsUnauthenticated proves the route is guarded: an
// unauthenticated caller is refused before any handler logic runs (fail-closed).
func TestManagedKeyRouteRejectsUnauthenticated(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithManagedKeys(&stubManagedKeys{}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/managed-keys", strings.NewReader(`{"algorithm":"ECDSA-P256"}`))
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("Idempotency-Key", "k1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated managed-keys status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}
