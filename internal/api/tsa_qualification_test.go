// SPDX-License-Identifier: MPL-2.0

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

const tsaQualificationTenant = "11111111-1111-4111-8111-111111111111"

func TestTSAQualificationIsTenantScopedEffectFreeAndExact(t *testing.T) {
	var calls int
	var seenTenant string
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithTSAQualificationPosture(func(_ context.Context, tenantID string) api.TSARuntimePosture {
			calls++
			seenTenant = tenantID
			return api.TSARuntimePosture{
				Configured: true, Served: true, Activated: true, Endpoint: "/tsa", TenantBound: true,
				StableCertificateReady: true, SignerReady: true, AuditReady: true,
				BulkheadReady: true, PolicyOID: "1.3.6.1.4.1.59551.2.1",
			}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/tsa/qualification", nil)
	req.Header.Set("X-Tenant-ID", tsaQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("TSA qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.TSAQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode TSA qualification: %v", err)
	}
	if calls != 1 || seenTenant != tsaQualificationTenant {
		t.Fatalf("posture source calls=%d tenant=%q, want one call for authenticated tenant", calls, seenTenant)
	}
	if !got.Ready || !got.EffectFree || got.Endpoint != "/tsa" || got.PolicyOID != "1.3.6.1.4.1.59551.2.1" {
		t.Fatalf("TSA qualification=%+v, want ready exact plan", got)
	}
	if len(got.Checks) != 8 || len(got.Blockers) != 0 || len(got.Proof) < 3 {
		t.Fatalf("TSA qualification checks=%d blockers=%v proof=%v", len(got.Checks), got.Blockers, got.Proof)
	}
	if len(got.PreviewWrites) != 0 || len(got.PreviewExternalEffects) != 0 || len(got.PreviewSignerCalls) != 0 {
		t.Fatalf("qualification claimed effects: writes=%v external=%v signer=%v", got.PreviewWrites, got.PreviewExternalEffects, got.PreviewSignerCalls)
	}
	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"private_key", "certificate_der", "certificate_pem", "signer_handle", "cert_file", "tenant_id"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("qualification exposed forbidden field %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestTSAQualificationFailsClosedWhenEvalProtocolProfileIsInactive(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithTSAQualificationPosture(func(context.Context, string) api.TSARuntimePosture {
			return api.TSARuntimePosture{
				Configured: true, Served: true, Activated: false, Endpoint: "/tsa", TenantBound: true,
				StableCertificateReady: true, SignerReady: true, AuditReady: true,
				BulkheadReady: true, PolicyOID: "1.3.6.1.4.1.59551.2.1",
			}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/tsa/qualification", nil)
	req.Header.Set("X-Tenant-ID", tsaQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("blocked TSA qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.TSAQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode blocked TSA qualification: %v", err)
	}
	if got.Ready {
		t.Fatalf("inactive protocol profile was reported ready: %+v", got)
	}
	if len(got.Blockers) != 1 || !strings.Contains(got.Blockers[0], "Protocol profile active") {
		t.Fatalf("inactive protocol profile blockers=%v, want one exact activation blocker", got.Blockers)
	}
}

func TestTSAQualificationFailsClosedAndNamesEveryBlockedGate(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithTSAQualificationPosture(func(context.Context, string) api.TSARuntimePosture {
			return api.TSARuntimePosture{Configured: true, Endpoint: "/tsa", PolicyOID: "1.3.6.1.4.1.59551.2.1"}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/tsa/qualification", nil)
	req.Header.Set("X-Tenant-ID", tsaQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("blocked TSA qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.TSAQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode blocked TSA qualification: %v", err)
	}
	if got.Ready || !got.EffectFree || len(got.Blockers) < 5 {
		t.Fatalf("blocked TSA qualification=%+v, want effect-free fail-closed result", got)
	}
	for _, check := range got.Checks {
		if !check.Passed && strings.TrimSpace(check.Recovery) == "" {
			t.Errorf("failed check %q has no recovery action", check.ID)
		}
	}
}

func TestTSAQualificationRouteIsRegisteredReadOnlyAndAuthenticated(t *testing.T) {
	var found bool
	for _, route := range api.New(nil, nil, nil).Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/v1/protocols/tsa/qualification" {
			found = true
			if route.Mutation {
				t.Fatal("TSA qualification is marked as a mutation; readiness preview must not require idempotency or authorize writes")
			}
		}
	}
	if !found {
		t.Fatal("TSA qualification route is not registered")
	}

	handler := api.New(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/tsa/qualification", nil)
	req.Header.Set("X-Tenant-ID", tsaQualificationTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated TSA qualification status=%d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}
