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
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/transit"
)

const transitPostureTenant = "11111111-1111-4111-8111-111111111111"

func transitRead(t *testing.T, handler http.Handler, path, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestTransitVersionHistoryIsCompleteTenantScopedAndMetadataOnly(t *testing.T) {
	ctx := context.Background()
	svc := transit.NewService(auditsink.Nop{})
	if _, err := svc.CreateKey(ctx, transitPostureTenant, "payments", transit.KindSign); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rotate(ctx, transitPostureTenant, "payments"); err != nil {
		t.Fatal(err)
	}

	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithTransit(svc))
	rec := transitRead(t, handler, "/api/v1/transit/keys/payments/versions", transitPostureTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("version history status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Versions []struct {
			Version int  `json:"version"`
			Current bool `json:"current"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "payments" || got.Kind != "sign" || len(got.Versions) != 2 || got.Versions[0].Version != 1 || got.Versions[0].Current || !got.Versions[1].Current {
		t.Fatalf("version history = %+v, want versions 1 and current 2", got)
	}
	for _, forbidden := range []string{"private", "pkcs8", "key_bytes", "material"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), forbidden) {
			t.Fatalf("metadata-only response exposed forbidden marker %q: %s", forbidden, rec.Body.String())
		}
	}

	rec = transitRead(t, handler, "/api/v1/transit/keys/payments/versions", "22222222-2222-4222-8222-222222222222")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant version history status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
}

func TestTransitPostureIsEffectFreeAndExplainsAutomaticRestoreAndKMIP(t *testing.T) {
	var calls int
	var seenTenant string
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithTransitPosture(func(_ context.Context, tenantID string) api.TransitRuntimePosture {
			calls++
			seenTenant = tenantID
			return api.TransitRuntimePosture{
				Served: true, PersistenceConfigured: true, SealedStateFound: true,
				KMIPConfigured: true, KMIPServed: true, KMIPListening: true,
				KMIPTenantBound: true, KMIPAddress: ":5696",
			}
		}),
	)
	rec := transitRead(t, handler, "/api/v1/transit/status", transitPostureTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("posture status=%d body=%s", rec.Code, rec.Body.String())
	}
	if calls != 1 || seenTenant != transitPostureTenant {
		t.Fatalf("posture calls=%d tenant=%q", calls, seenTenant)
	}
	var got api.TransitPosture
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.EffectFree || !got.Transit.Served || !got.Transit.RecoveryReady || got.Transit.RestoreState != "restored" {
		t.Fatalf("transit posture = %+v", got.Transit)
	}
	if got.KMIP.State != "listening" || !got.KMIP.TenantBound || got.KMIP.Transport != "mTLS" || len(got.KMIP.Operations) < 5 {
		t.Fatalf("KMIP posture = %+v", got.KMIP)
	}
	if len(got.RecoverySteps) < 3 || len(got.Proof) < 3 {
		t.Fatalf("recovery=%v proof=%v", got.RecoverySteps, got.Proof)
	}
	for _, forbidden := range []string{"private_key", "key_bytes", "cert_file", "client_ca_file", "tenant_id"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), forbidden) {
			t.Fatalf("posture exposed forbidden field %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestTransitPostureFailsVisibleWhenPersistenceAndKMIPAreOff(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithTransitPosture(func(context.Context, string) api.TransitRuntimePosture {
		return api.TransitRuntimePosture{Served: true}
	}))
	rec := transitRead(t, handler, "/api/v1/transit/status", transitPostureTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("posture status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got api.TransitPosture
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Transit.RecoveryReady || got.Transit.RestoreState != "volatile" || got.Transit.Recovery == "" {
		t.Fatalf("volatile transit posture = %+v", got.Transit)
	}
	if got.KMIP.State != "not_configured" || got.KMIP.Recovery == "" {
		t.Fatalf("disabled KMIP posture = %+v", got.KMIP)
	}
}

func TestTransitRecoveryRoutesAreRegisteredReadOnlyAndAuthenticated(t *testing.T) {
	routes := api.New(nil, nil, nil).Routes()
	want := map[string]bool{"getTransitPosture": false, "listTransitKeyVersions": false}
	for _, route := range routes {
		if _, ok := want[route.OperationID]; !ok {
			continue
		}
		want[route.OperationID] = true
		if route.Mutation || route.Permission != "keys:read" {
			t.Fatalf("route %s mutation=%v permission=%q, want read-only keys:read", route.OperationID, route.Mutation, route.Permission)
		}
	}
	for operation, found := range want {
		if !found {
			t.Errorf("route %s is not registered", operation)
		}
	}
}
