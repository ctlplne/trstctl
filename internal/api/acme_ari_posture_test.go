// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

func TestACMEARIPostureRouteIsReadOnlyTenantScopedAndFailsHonestly(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	calls := 0
	var gotTenant string
	provider := func(_ context.Context, tenant, after string, limit int, at time.Time) (ACMEARIPosture, string, error) {
		calls++
		gotTenant = tenant
		if after != "00000000-0000-0000-0000-000000000000" || limit != 20 || at.IsZero() {
			t.Fatalf("provider page/time = after:%q limit:%d at:%s", after, limit, at)
		}
		return ACMEARIPosture{
			Served: true, GeneratedAt: at,
			PublicationStatus:   ACMEARIPublicationServed,
			PublicationEndpoint: "/acme/renewal-info/{certid}",
			SchedulerStatus:     ACMEARISchedulerEnabled,
			Items: []ACMEARICertificatePosture{{
				CertificateID:     "22222222-2222-4222-8222-222222222222",
				CertificateStatus: "active",
				PublicationStatus: ACMEARICertificatePublished,
				SchedulerStatus:   ACMEARIRunPending,
				SchedulerSource:   ACMEARISourceNone,
			}},
		}, "", nil
	}
	handler := New(nil, nil, nil, WithInsecureHeaderResolver(), WithACMEARIPosture(provider))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "ari-reader")
	req.Header.Set("X-Roles", "viewer")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ARI posture status=%d body=%s", rec.Code, rec.Body.String())
	}
	if calls != 1 || gotTenant != tenantID {
		t.Fatalf("provider calls=%d tenant=%q, want one call for authenticated tenant", calls, gotTenant)
	}
	var got ACMEARIPosture
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode ARI posture: %v", err)
	}
	if !got.Served || len(got.Items) != 1 || got.Items[0].PublicationStatus != ACMEARICertificatePublished {
		t.Fatalf("ARI posture lost provider truth: %+v", got)
	}
	if req.Header.Get("Idempotency-Key") != "" {
		t.Fatal("read-only ARI request unexpectedly required an idempotency key")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture?cursor=not-base64", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "ari-reader")
	req.Header.Set("X-Roles", "viewer")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || calls != 1 {
		t.Fatalf("invalid ARI cursor status=%d calls=%d, want 400 without provider call", rec.Code, calls)
	}

	const afterID = "33333333-3333-4333-8333-333333333333"
	emptyCalls := 0
	emptyProvider := func(_ context.Context, tenant, after string, limit int, at time.Time) (ACMEARIPosture, string, error) {
		emptyCalls++
		wantAfter := "00000000-0000-0000-0000-000000000000"
		nextID := afterID
		if emptyCalls == 2 {
			wantAfter = afterID
			nextID = ""
		}
		if tenant != tenantID || after != wantAfter || limit != 7 || at.IsZero() {
			t.Fatalf("paginated provider input = tenant:%q after:%q limit:%d at:%s", tenant, after, limit, at)
		}
		return ACMEARIPosture{
			Served:            true,
			GeneratedAt:       at,
			PublicationStatus: ACMEARIPublicationServed,
			SchedulerStatus:   ACMEARISchedulerEnabled,
		}, nextID, nil
	}
	emptyHandler := New(nil, nil, nil, WithInsecureHeaderResolver(), WithACMEARIPosture(emptyProvider))
	req = httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture?limit=7", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "ari-reader")
	req.Header.Set("X-Roles", "viewer")
	rec = httptest.NewRecorder()
	emptyHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty paginated ARI posture status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode empty paginated ARI posture: %v", err)
	}
	if got.Items == nil || len(got.Items) != 0 {
		t.Fatalf("empty ARI items = %#v, want non-nil []", got.Items)
	}
	if got.NextCursor != encodeCursor(afterID) {
		t.Fatalf("next_cursor = %q, want opaque cursor %q", got.NextCursor, encodeCursor(afterID))
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture?limit=7&cursor="+got.NextCursor, nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "ari-reader")
	req.Header.Set("X-Roles", "viewer")
	rec = httptest.NewRecorder()
	emptyHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || emptyCalls != 2 {
		t.Fatalf("round-trip ARI cursor status=%d provider calls=%d body=%s", rec.Code, emptyCalls, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || calls != 1 {
		t.Fatalf("unauthenticated ARI posture status=%d calls=%d, want 401 without provider call", rec.Code, calls)
	}

	issuerOnly := authz.Role{Name: "ari-issuer-only", Permissions: []authz.Permission{authz.IssuersRead}}
	restricted := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(issuerOnly), WithACMEARIPosture(provider))
	req = httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "issuer-reader")
	req.Header.Set("X-Roles", issuerOnly.Name)
	rec = httptest.NewRecorder()
	restricted.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || calls != 1 {
		t.Fatalf("issuer-only ARI posture status=%d calls=%d, want 403 without provider call", rec.Code, calls)
	}

	unwired := New(nil, nil, nil, WithInsecureHeaderResolver())
	req = httptest.NewRequest(http.MethodGet, "/api/v1/acme/ari/posture", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Roles", "viewer")
	rec = httptest.NewRecorder()
	unwired.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired ARI posture status=%d body=%s, want 503", rec.Code, rec.Body.String())
	}
}
