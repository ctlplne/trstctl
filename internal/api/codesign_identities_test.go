// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

func fetchCodeSigningIdentities(t *testing.T, handler http.Handler, authenticated bool) (int, api.CodeSigningIdentityList) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/code-signing/identities", nil)
	if authenticated {
		req.Header.Set("X-Tenant-ID", connectorTenantA)
		req.Header.Set("X-Roles", "admin")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body api.CodeSigningIdentityList
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, body
}

// B-4: code signing served the two mutations and nothing that answered
// afterwards — which identities signed, and did the transparency entry land.
// These pin the counts a reviewer asks for first.
func TestCodeSigningIdentitiesReportTransparencyState(t *testing.T) {
	signed := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithCodeSigningIdentities(func(_ context.Context, tenantID string) ([]api.CodeSigningIdentity, error) {
			if tenantID != connectorTenantA {
				t.Errorf("provider called with tenant %q", tenantID)
			}
			return []api.CodeSigningIdentity{
				{OperationID: "op-1", Mode: "keyless", Status: "succeeded", RequestHash: "sha256:aaa", Transparency: "verified", CreatedAt: signed, UpdatedAt: signed},
				{OperationID: "op-2", Mode: "managed", Status: "succeeded", RequestHash: "sha256:bbb", Transparency: "pending", CreatedAt: signed, UpdatedAt: signed},
				{OperationID: "op-3", Mode: "managed", Status: "succeeded", RequestHash: "sha256:ccc", Transparency: "not-published", CreatedAt: signed, UpdatedAt: signed},
				{OperationID: "op-4", Mode: "keyless", Status: "failed", RequestHash: "sha256:ddd", Transparency: "failed", TransparencyError: "rekor: invalid transparency receipt", CreatedAt: signed, UpdatedAt: signed},
			}, nil
		}),
	)

	code, body := fetchCodeSigningIdentities(t, handler, true)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body.Total != 4 {
		t.Fatalf("total = %d, want 4", body.Total)
	}
	// Only a delivered (receipt-verified) entry counts as verified.
	if body.VerifiedCount != 1 {
		t.Fatalf("verified_count = %d, want 1 — pending and failed are not verified", body.VerifiedCount)
	}
	if body.NotPublishedCount != 1 {
		t.Fatalf("not_published_count = %d, want 1", body.NotPublishedCount)
	}
	// A failed publication must carry the reason, so an operator can act.
	if body.Items[3].TransparencyError == "" {
		t.Fatal("failed transparency row dropped its error")
	}
	// Both identity kinds survive the round trip.
	if body.Items[0].Mode != "keyless" || body.Items[1].Mode != "managed" {
		t.Fatalf("modes = %q/%q", body.Items[0].Mode, body.Items[1].Mode)
	}
}

func TestCodeSigningIdentitiesEmptyAndUnwired(t *testing.T) {
	empty := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithCodeSigningIdentities(func(context.Context, string) ([]api.CodeSigningIdentity, error) { return nil, nil }),
	)
	code, body := fetchCodeSigningIdentities(t, empty, true)
	if code != http.StatusOK || body.Items == nil || body.Total != 0 {
		t.Fatalf("empty = %d %+v", code, body)
	}

	unwired := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	code, body = fetchCodeSigningIdentities(t, unwired, true)
	if code != http.StatusOK || body.Items == nil {
		t.Fatalf("unwired = %d %+v", code, body)
	}
}

func TestCodeSigningIdentitiesSurfaceReadFailure(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithCodeSigningIdentities(func(context.Context, string) ([]api.CodeSigningIdentity, error) {
			return nil, errors.New("read failed")
		}),
	)
	if code, _ := fetchCodeSigningIdentities(t, handler, true); code == http.StatusOK {
		t.Fatal("a failing read reported success")
	}
}

func TestCodeSigningIdentitiesRequireAuthenticatedTenant(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithCodeSigningIdentities(func(context.Context, string) ([]api.CodeSigningIdentity, error) {
			return []api.CodeSigningIdentity{{OperationID: "op-1", Mode: "keyless"}}, nil
		}),
	)
	if code, _ := fetchCodeSigningIdentities(t, handler, false); code == http.StatusOK {
		t.Fatal("unauthenticated caller received signing identities")
	}
}
