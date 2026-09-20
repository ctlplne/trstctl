// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

const spiffeQualificationTenant = "11111111-1111-4111-8111-111111111111"

func TestSPIFFEQualificationIsTenantScopedEffectFreeAndExact(t *testing.T) {
	var calls int
	var seenTenant string
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSPIFFEQualificationPosture(func(_ context.Context, tenantID string) api.SPIFFERuntimePosture {
			calls++
			seenTenant = tenantID
			return api.SPIFFERuntimePosture{
				Configured: true, Served: true, Activated: true, TenantBound: true,
				TrustDomain: "workloads.example.test", SocketURI: "unix:///run/trstctl-spiffe/workload.sock",
				SocketReady: true, SocketOwnerOnly: true, SocketMode: "Srwx------",
				RegistrationEntryCount: 1, IssuingPathReady: true, BulkheadReady: true,
				LocalSocketDeprecated: true,
				SupportedOperations:   []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTSVID", "FetchJWTBundles", "ValidateJWTSVID"},
			}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/spiffe/qualification", nil)
	req.Header.Set("X-Tenant-ID", spiffeQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("SPIFFE qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.SPIFFEQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode SPIFFE qualification: %v", err)
	}
	if calls != 1 || seenTenant != spiffeQualificationTenant {
		t.Fatalf("posture source calls=%d tenant=%q, want one call for authenticated tenant", calls, seenTenant)
	}
	if !got.Ready || !got.EffectFree || got.TrustDomain != "workloads.example.test" || got.Transport != "unix" {
		t.Fatalf("SPIFFE qualification=%+v, want exact ready UDS plan", got)
	}
	if got.SocketURI != "unix:///run/trstctl-spiffe/workload.sock" || got.RegistrationEntryCount != 1 || !got.LocalSocketDeprecated {
		t.Fatalf("SPIFFE runtime facts=%+v, want exact served posture", got)
	}
	if len(got.Checks) != 9 || len(got.Blockers) != 0 || len(got.Proof) < 3 || len(got.SupportedOperations) != 5 {
		t.Fatalf("SPIFFE qualification checks=%d blockers=%v proof=%v operations=%v", len(got.Checks), got.Blockers, got.Proof, got.SupportedOperations)
	}
	if len(got.PreviewWrites) != 0 || len(got.PreviewExternalEffects) != 0 || len(got.PreviewSignerCalls) != 0 {
		t.Fatalf("qualification claimed effects: writes=%v external=%v signer=%v", got.PreviewWrites, got.PreviewExternalEffects, got.PreviewSignerCalls)
	}
	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"private_key", "jwt_svid", "x509_svid", "bundle_pem", "certificate_der", "token", "selector_value", "key_bytes", "secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("qualification exposed forbidden field %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestSPIFFEQualificationFailsClosedAndNamesEveryBlockedGate(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSPIFFEQualificationPosture(func(context.Context, string) api.SPIFFERuntimePosture {
			return api.SPIFFERuntimePosture{Configured: true, TrustDomain: "workloads.example.test", SocketURI: "unix:///run/trstctl-spiffe/workload.sock"}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/spiffe/qualification", nil)
	req.Header.Set("X-Tenant-ID", spiffeQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("blocked SPIFFE qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.SPIFFEQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode blocked SPIFFE qualification: %v", err)
	}
	if got.Ready || !got.EffectFree || len(got.Blockers) < 7 {
		t.Fatalf("blocked SPIFFE qualification=%+v, want effect-free fail-closed result", got)
	}
	for _, check := range got.Checks {
		if !check.Passed && strings.TrimSpace(check.Recovery) == "" {
			t.Errorf("failed check %q has no recovery action", check.ID)
		}
	}
}

func TestSPIFFEQualificationRouteIsRegisteredReadOnlyAndAuthenticated(t *testing.T) {
	var found bool
	for _, route := range api.New(nil, nil, nil).Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/v1/protocols/spiffe/qualification" {
			found = true
			if route.Mutation {
				t.Fatal("SPIFFE qualification is marked as a mutation; read-only review must not require idempotency or authorize writes")
			}
		}
	}
	if !found {
		t.Fatal("SPIFFE qualification route is not registered")
	}

	handler := api.New(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/spiffe/qualification", nil)
	req.Header.Set("X-Tenant-ID", spiffeQualificationTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated SPIFFE qualification status=%d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}
