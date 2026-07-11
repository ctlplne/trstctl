// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// stubManagedKeys is a minimal ManagedKeyService used to prove the served route is
// wired and reaches the service. The lifecycle itself is covered end to end against
// a fake KMS in ee/managedkeys; here we only assert HTTP wiring/fail-closed.
type stubManagedKeys struct {
	generated     bool
	generateCalls int
	rotateCalls   int
	revokeCalls   int
	zeroizeCalls  int
	lastAlgorithm crypto.Algorithm
	lastKeyID     string
	lastRequester string
	lastIdem      string
	lastBinding   string
	err           error
}

func (s *stubManagedKeys) Generate(_ context.Context, _ string, alg crypto.Algorithm, idempotencyKey, requestBinding string) (api.ManagedKey, error) {
	s.generated = true
	s.generateCalls++
	s.lastAlgorithm = alg
	s.lastIdem = idempotencyKey
	s.lastBinding = requestBinding
	if s.err != nil {
		return api.ManagedKey{}, s.err
	}
	return api.ManagedKey{KeyID: "fake-kms-key-0001", Algorithm: alg, Version: 1, State: "active"}, nil
}
func (s *stubManagedKeys) Rotate(_ context.Context, _, keyID, requester, idempotencyKey, requestBinding string) (api.ManagedKey, error) {
	s.rotateCalls++
	s.lastKeyID, s.lastRequester, s.lastIdem = keyID, requester, idempotencyKey
	s.lastBinding = requestBinding
	if s.err != nil {
		return api.ManagedKey{}, s.err
	}
	return api.ManagedKey{KeyID: "fake-kms-key-0002", Algorithm: crypto.ECDSAP256, Version: 2, State: "active"}, nil
}
func (s *stubManagedKeys) Revoke(_ context.Context, _, keyID, requester, idempotencyKey, requestBinding string) (api.ManagedKey, error) {
	s.revokeCalls++
	s.lastKeyID, s.lastRequester, s.lastIdem = keyID, requester, idempotencyKey
	s.lastBinding = requestBinding
	if s.err != nil {
		return api.ManagedKey{}, s.err
	}
	return api.ManagedKey{KeyID: "fake-kms-key-0001", Algorithm: crypto.ECDSAP256, Version: 1, State: "revoked"}, nil
}
func (s *stubManagedKeys) Zeroize(_ context.Context, _, keyID, requester, idempotencyKey, requestBinding string) (api.ManagedKey, error) {
	s.zeroizeCalls++
	s.lastKeyID, s.lastRequester, s.lastIdem = keyID, requester, idempotencyKey
	s.lastBinding = requestBinding
	if s.err != nil {
		return api.ManagedKey{}, s.err
	}
	return api.ManagedKey{KeyID: "fake-kms-key-0001", Algorithm: crypto.ECDSAP256, Version: 1, State: "zeroized"}, nil
}

const managedKeyTestTenant = "11111111-1111-1111-1111-111111111111"

func managedKeyRequest(t *testing.T, handler http.Handler, path, idempotencyKey, subject, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	req.Header.Set("X-Tenant-ID", managedKeyTestTenant)
	req.Header.Set("X-Subject", subject)
	req.Header.Set("X-Roles", "admin")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func managedKeyHarness(service *stubManagedKeys, idem *orchestrator.Idempotency) http.Handler {
	return api.New(nil, idem, nil, api.WithInsecureHeaderResolver(), api.WithManagedKeys(service))
}

func managedKeyServiceCalls(service *stubManagedKeys) int {
	return service.generateCalls + service.rotateCalls + service.revokeCalls + service.zeroizeCalls
}

func TestManagedKeyIdempotencyExactReplayInvokesEachServiceActionOnce(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
		calls      func(*stubManagedKeys) int
	}{
		{name: "generate", path: "/api/v1/managed-keys", body: `{"algorithm":"ECDSA-P256"}`, wantStatus: http.StatusCreated, calls: func(s *stubManagedKeys) int { return s.generateCalls }},
		{name: "rotate", path: "/api/v1/managed-keys/rotate", body: `{"key_id":"fake-kms-key-0001"}`, wantStatus: http.StatusOK, calls: func(s *stubManagedKeys) int { return s.rotateCalls }},
		{name: "revoke", path: "/api/v1/managed-keys/revoke", body: `{"key_id":"fake-kms-key-0001"}`, wantStatus: http.StatusOK, calls: func(s *stubManagedKeys) int { return s.revokeCalls }},
		{name: "zeroize", path: "/api/v1/managed-keys/zeroize", body: `{"key_id":"fake-kms-key-0001"}`, wantStatus: http.StatusOK, calls: func(s *stubManagedKeys) int { return s.zeroizeCalls }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &stubManagedKeys{}
			idempotencyKey := "managed-key-exact-" + test.name
			handler := managedKeyHarness(service, orchestrator.NewMemoryIdempotency())
			first := managedKeyRequest(t, handler, test.path, idempotencyKey, "operator-a", test.body)
			replay := managedKeyRequest(t, handler, test.path, idempotencyKey, "operator-a", test.body)

			if first.Code != test.wantStatus || replay.Code != test.wantStatus {
				t.Fatalf("exact replay statuses=(%d,%d), want %d; first=%s replay=%s", first.Code, replay.Code, test.wantStatus, first.Body.String(), replay.Body.String())
			}
			if !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) {
				t.Fatalf("exact replay body differs: first=%s replay=%s", first.Body.String(), replay.Body.String())
			}
			if got := test.calls(service); got != 1 || managedKeyServiceCalls(service) != 1 {
				t.Fatalf("service callback calls=%d total=%d, want one %s callback", got, managedKeyServiceCalls(service), test.name)
			}
			if service.lastIdem != idempotencyKey {
				t.Fatalf("service idempotency key=%q, want raw header %q", service.lastIdem, idempotencyKey)
			}
			if service.lastBinding == "" {
				t.Fatal("service did not receive the authenticated canonical request binding")
			}
			if test.name == "generate" {
				if service.lastAlgorithm != crypto.ECDSAP256 {
					t.Fatalf("service algorithm=%q, want decoded %q", service.lastAlgorithm, crypto.ECDSAP256)
				}
			} else if service.lastKeyID != "fake-kms-key-0001" || service.lastRequester != "operator-a" {
				t.Fatalf("service action args key=%q requester=%q, want decoded key and authenticated subject", service.lastKeyID, service.lastRequester)
			}
		})
	}
}

func TestManagedKeyIdempotencyRejectsChangedActionBodyOrCallerBeforeService(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		body    string
		subject string
	}{
		{name: "body", path: "/api/v1/managed-keys", body: `{"algorithm":"RSA-2048"}`, subject: "operator-a"},
		{name: "caller", path: "/api/v1/managed-keys", body: `{"algorithm":"ECDSA-P256"}`, subject: "operator-b"},
		{name: "action", path: "/api/v1/managed-keys/revoke", body: `{"key_id":"fake-kms-key-0001"}`, subject: "operator-a"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &stubManagedKeys{}
			handler := managedKeyHarness(service, orchestrator.NewMemoryIdempotency())
			const rawKey = "managed-key-shared-collision"
			first := managedKeyRequest(t, handler, "/api/v1/managed-keys", rawKey, "operator-a", `{"algorithm":"ECDSA-P256"}`)
			if first.Code != http.StatusCreated || service.generateCalls != 1 {
				t.Fatalf("baseline status=%d calls=%d body=%s", first.Code, service.generateCalls, first.Body.String())
			}

			collision := managedKeyRequest(t, handler, test.path, rawKey, test.subject, test.body)
			if collision.Code != http.StatusConflict {
				t.Fatalf("changed %s status=%d body=%s, want 409", test.name, collision.Code, collision.Body.String())
			}
			if got := managedKeyServiceCalls(service); got != 1 {
				t.Fatalf("changed %s reached service; total calls=%d, want baseline call only", test.name, got)
			}
		})
	}
}

func TestManagedKeyIdempotencyCredentialCacheCollisionReturnsCredentialFreeConflict(t *testing.T) {
	const (
		rawKey     = "credential-bearing-cache-collision"
		credential = "credential-sentinel-that-must-not-escape"
	)
	idem := orchestrator.NewMemoryIdempotency()
	if _, err := idem.Do(context.Background(), managedKeyTestTenant, rawKey, func(context.Context) ([]byte, error) {
		return []byte(`{"s":201,"b":{"token":"` + credential + `"}}`), nil
	}); err != nil {
		t.Fatalf("preseed credential-bearing cachedResponse: %v", err)
	}
	service := &stubManagedKeys{}
	handler := managedKeyHarness(service, idem)

	collision := managedKeyRequest(t, handler, "/api/v1/managed-keys/revoke", rawKey, "operator-b", `{"key_id":"fake-kms-key-0001"}`)
	if collision.Code != http.StatusConflict {
		t.Fatalf("credential-cache collision status=%d body=%s, want 409", collision.Code, collision.Body.String())
	}
	if strings.Contains(collision.Body.String(), credential) {
		t.Fatalf("409 disclosed cached credential: %s", collision.Body.String())
	}
	if got := managedKeyServiceCalls(service); got != 0 {
		t.Fatalf("credential-cache collision reached service/approval path %d times, want zero", got)
	}
}

func TestManagedKeyValidationRunsBeforeIdempotencyReplay(t *testing.T) {
	service := &stubManagedKeys{}
	handler := managedKeyHarness(service, orchestrator.NewMemoryIdempotency())
	const rawKey = "managed-key-validate-before-replay"
	first := managedKeyRequest(t, handler, "/api/v1/managed-keys", rawKey, "operator-a", `{"algorithm":"ECDSA-P256"}`)
	if first.Code != http.StatusCreated || service.generateCalls != 1 {
		t.Fatalf("baseline status=%d calls=%d body=%s", first.Code, service.generateCalls, first.Body.String())
	}

	malformed := managedKeyRequest(t, handler, "/api/v1/managed-keys", rawKey, "operator-a", `{`)
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed replay status=%d body=%s, want 400 before cached response", malformed.Code, malformed.Body.String())
	}
	if service.generateCalls != 1 {
		t.Fatalf("malformed replay reached service; calls=%d, want baseline call only", service.generateCalls)
	}

	unsupported := managedKeyRequest(t, handler, "/api/v1/managed-keys", "managed-key-unsupported", "operator-a", `{"algorithm":"not-an-algorithm"}`)
	if unsupported.Code != http.StatusBadRequest {
		t.Fatalf("unsupported algorithm status=%d body=%s, want 400", unsupported.Code, unsupported.Body.String())
	}
	if service.generateCalls != 1 {
		t.Fatalf("unsupported algorithm reached service; calls=%d, want baseline call only", service.generateCalls)
	}
}

func TestManagedKeyServiceIdempotencyDriftMapsToConflict(t *testing.T) {
	service := &stubManagedKeys{err: orchestrator.ErrIdempotencyConflict}
	handler := managedKeyHarness(service, orchestrator.NewMemoryIdempotency())
	response := managedKeyRequest(t, handler, "/api/v1/managed-keys", "managed-key-lower-drift", "operator-a", `{"algorithm":"ECDSA-P256"}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("service drift status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if service.generateCalls != 1 {
		t.Fatalf("service drift generate calls=%d, want one", service.generateCalls)
	}
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
