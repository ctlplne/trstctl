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

const cmpQualificationTenant = "11111111-1111-4111-8111-111111111111"

func TestCMPQualificationIsTenantScopedEffectFreeAndExact(t *testing.T) {
	var calls int
	var seenTenant string
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithCMPQualificationPosture(func(_ context.Context, tenantID string) api.CMPRuntimePosture {
			calls++
			seenTenant = tenantID
			return api.CMPRuntimePosture{
				Configured: true, Served: true, Endpoint: "/cmp", TenantBound: true,
				RATransportReady: true, ClientTrustAnchorCount: 2,
				IssuingPathReady: true, ProfileName: "device-90d", ProfileReady: true,
				BindingMode: "subject-bound", BulkheadReady: true,
			}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/cmp/qualification", nil)
	req.Header.Set("X-Tenant-ID", cmpQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("CMP qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.CMPQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode CMP qualification: %v", err)
	}
	if calls != 1 || seenTenant != cmpQualificationTenant {
		t.Fatalf("posture source calls=%d tenant=%q, want one call for authenticated tenant", calls, seenTenant)
	}
	if !got.Ready || !got.EffectFree || got.Endpoint != "/cmp" || got.Profile != "device-90d" || got.BindingMode != "subject-bound" {
		t.Fatalf("CMP qualification=%+v, want ready exact subject-bound plan", got)
	}
	if len(got.Checks) != 8 || len(got.Blockers) != 0 || len(got.Proof) < 3 {
		t.Fatalf("CMP qualification checks=%d blockers=%v proof=%v", len(got.Checks), got.Blockers, got.Proof)
	}
	if len(got.PreviewWrites) != 0 || len(got.PreviewExternalEffects) != 0 || len(got.PreviewSignerCalls) != 0 {
		t.Fatalf("qualification claimed effects: writes=%v external=%v signer=%v", got.PreviewWrites, got.PreviewExternalEffects, got.PreviewSignerCalls)
	}
	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"private_key", "client_certificate", "pkimessage_der", "csr_der", "trust_anchor_pem", "ra_key_file"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("qualification exposed forbidden field %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestCMPQualificationFailsClosedAndNamesEveryBlockedGate(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithCMPQualificationPosture(func(context.Context, string) api.CMPRuntimePosture {
			return api.CMPRuntimePosture{Configured: true, Endpoint: "/cmp", ProfileName: "default", BindingMode: "subject-bound"}
		}),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/cmp/qualification", nil)
	req.Header.Set("X-Tenant-ID", cmpQualificationTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("blocked CMP qualification status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var got api.CMPQualification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode blocked CMP qualification: %v", err)
	}
	if got.Ready || !got.EffectFree || len(got.Blockers) < 6 {
		t.Fatalf("blocked CMP qualification=%+v, want effect-free fail-closed result", got)
	}
	for _, check := range got.Checks {
		if !check.Passed && strings.TrimSpace(check.Recovery) == "" {
			t.Errorf("failed check %q has no recovery action", check.ID)
		}
	}
}

func TestCMPQualificationRouteIsRegisteredReadOnlyAndAuthenticated(t *testing.T) {
	var found bool
	for _, route := range api.New(nil, nil, nil).Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/v1/protocols/cmp/qualification" {
			found = true
			if route.Mutation {
				t.Fatal("CMP qualification is marked as a mutation; read-only preview must not require idempotency or authorize writes")
			}
		}
	}
	if !found {
		t.Fatal("CMP qualification route is not registered")
	}

	handler := api.New(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/protocols/cmp/qualification", nil)
	req.Header.Set("X-Tenant-ID", cmpQualificationTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated CMP qualification status=%d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}
