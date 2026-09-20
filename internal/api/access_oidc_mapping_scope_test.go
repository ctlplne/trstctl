// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestOIDCMappingStatusIsTenantScoped(t *testing.T) {
	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"
	const tenantC = "33333333-3333-3333-3333-333333333333"
	mappings := []AuthTenantMapping{
		{Subject: "alice", TenantID: tenantA, Roles: []string{"viewer"}},
		{Claim: "acme", TenantID: tenantA, Roles: []string{"operator"}},
		{Group: "acme-admins", TenantID: tenantA, Roles: []string{"admin"}},
		{Subject: "bob", TenantID: tenantB, Roles: []string{"viewer"}},
		{Group: "beta-admins", TenantID: tenantB, Roles: []string{"admin"}},
	}
	cfg := AuthConfig{OIDCEnabled: true, TenantClaim: "org", GroupsClaim: "groups", ClaimIsTenant: true,
		DefaultRoles: []string{"viewer"}, DefaultTenant: tenantA, AllowDefaultTenant: true, TenantMappings: mappings}
	before, err := json.Marshal(cfg.TenantMappings)
	if err != nil {
		t.Fatal(err)
	}
	role := authz.Role{Name: "mapping-reader", Permissions: []authz.Permission{authz.AccessRead}}
	var principal authz.Principal
	var resolveErr error
	h := New(nil, nil, nil, WithAuth(cfg), WithRoles(role), WithPrincipalResolver(func(*http.Request) (authz.Principal, error) {
		return principal, resolveErr
	}))
	for _, tc := range []struct {
		name, tenant, header  string
		permission, anonymous bool
		wantStatus            int
		wantMappings          []AuthTenantMapping
		wantDefault           string
	}{
		{name: "A retains its subject claim and group rules", tenant: tenantA, permission: true, wantStatus: 200, wantMappings: mappings[:3], wantDefault: tenantA},
		{name: "B cannot read A rules or fallback", tenant: tenantB, permission: true, wantStatus: 200, wantMappings: mappings[3:]},
		{name: "unmapped tenant gets empty array", tenant: tenantC, permission: true, wantStatus: 200, wantMappings: []AuthTenantMapping{}},
		{name: "foreign assertion rejected", tenant: tenantB, header: tenantA, permission: true, wantStatus: 403},
		{name: "permission still required", tenant: tenantB, wantStatus: 403},
		{name: "anonymous rejected", anonymous: true, wantStatus: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal = authz.Principal{TenantID: tc.tenant, Subject: "reader"}
			resolveErr = nil
			if tc.anonymous {
				resolveErr = errors.New("no credentials")
			}
			if tc.permission {
				principal.Grants = []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: tc.tenant}}}
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/access/oidc-mapping", nil)
			if tc.header != "" {
				req.Header.Set("X-Tenant-ID", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			var got oidcMappingResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.TenantMappings, tc.wantMappings) {
				t.Errorf("mappings = %+v, want only %+v", got.TenantMappings, tc.wantMappings)
			}
			if got.DefaultTenant != tc.wantDefault || got.AllowDefaultTenant != (tc.wantDefault != "") {
				t.Errorf("fallback = %q/%v, want %q/%v", got.DefaultTenant, got.AllowDefaultTenant, tc.wantDefault, tc.wantDefault != "")
			}
			if !got.Enabled || got.TenantClaim != "org" || got.GroupsClaim != "groups" || !got.ClaimIsTenant || !reflect.DeepEqual(got.DefaultRoles, []string{"viewer"}) {
				t.Errorf("common mapping settings changed: %+v", got)
			}
		})
	}
	after, err := json.Marshal(cfg.TenantMappings)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("status request mutated authentication configuration")
	}
}

func TestOIDCMappingStatusWithoutAuthConfiguration(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	role := authz.Role{Name: "mapping-reader", Permissions: []authz.Permission{authz.AccessRead}}
	h := New(nil, nil, nil, WithRoles(role), WithPrincipalResolver(func(*http.Request) (authz.Principal, error) {
		return authz.Principal{TenantID: tenantID, Subject: "reader", Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: tenantID}}}}, nil
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/access/oidc-mapping", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"tenant_mappings":[]`) || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled mapping status = %d: %s", rec.Code, rec.Body.String())
	}
}
