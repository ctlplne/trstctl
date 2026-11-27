// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestServedMemberOffboardRequiresRoleAssignment(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-admin", []string{string(authz.Wildcard)})
	writer := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-writer", []string{string(authz.AccessWrite)})
	upsertMember(t, h.ts, admin, "retiring-member", []string{"viewer"})
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/members/retiring-member/offboard",
		writer, "member-offboard-role-check", map[string]string{"reason": "completed access review"})
	if code != http.StatusForbidden {
		t.Fatalf("offboard without role assignment permission = %d, want 403; body=%s", code, body)
	}
	member, err := h.store.GetTenantMember(t.Context(), h.tenant, "retiring-member")
	if err != nil || member.Status != "active" {
		t.Fatalf("member after refused offboard = %+v, err=%v", member, err)
	}
	perms := authz.BuiltinRoles()["operator"].Permissions
	operatorScopes := make([]string, len(perms))
	for i, permission := range perms {
		operatorScopes[i] = string(permission)
	}
	operator := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-operator", operatorScopes)
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/members/retiring-member/offboard",
		operator, "member-offboard-authorized", map[string]string{"reason": "completed access review"})
	if code != http.StatusOK {
		t.Fatalf("authorized member offboard = %d, want 200; body=%s", code, body)
	}
}

func TestServedMemberAuthorityPreservesHigherRoles(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		body               any
	}{
		{name: "offboard", method: http.MethodPost, path: "/api/v1/access/members/protected-member/offboard",
			body: map[string]string{"reason": "completed access review"}},
		{name: "replace", method: http.MethodPut, path: "/api/v1/access/members/protected-member",
			body: map[string]any{"roles": []string{"viewer"}, "source": "manual"}},
		{name: "clear", method: http.MethodPut, path: "/api/v1/access/members/protected-member",
			body: map[string]any{"roles": []string{}, "source": "manual"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{})
			admin := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-admin", []string{string(authz.Wildcard)})
			perms := authz.BuiltinRoles()["operator"].Permissions
			operatorScopes := make([]string, len(perms))
			for i, permission := range perms {
				operatorScopes[i] = string(permission)
			}
			operator := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-operator", operatorScopes)
			upsertMember(t, h.ts, admin, "protected-member", []string{"admin"})
			code, body := doBearer(t, h.ts, test.method, test.path, operator, "member-authority-"+test.name, test.body)
			if code != http.StatusForbidden {
				t.Fatalf("member authority change = %d, want 403; body=%s", code, body)
			}
			member, err := h.store.GetTenantMember(t.Context(), h.tenant, "protected-member")
			if err != nil || member.Status != "active" || len(member.Roles) != 1 || member.Roles[0] != "admin" {
				t.Fatalf("member authority after refused change = %+v, err=%v", member, err)
			}
		})
	}
}

func TestServedMemberAuthorityPreservesLastAdministrator(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-admin", []string{string(authz.Wildcard)})
	upsertMember(t, h.ts, admin, "first-admin", []string{"admin"})
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/members/first-admin/offboard",
		admin, "member-last-admin-offboard", map[string]string{"reason": "completed access review"})
	if code != http.StatusForbidden {
		t.Fatalf("last administrator offboard = %d, want 403; body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/first-admin",
		admin, "member-last-admin-replace", map[string]any{"roles": []string{"viewer"}, "source": "manual"})
	if code != http.StatusForbidden {
		t.Fatalf("last administrator replacement = %d, want 403; body=%s", code, body)
	}
	upsertMember(t, h.ts, admin, "second-admin", []string{"admin"})
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/members/first-admin/offboard",
		admin, "member-first-admin-offboard", map[string]string{"reason": "completed access review"})
	if code != http.StatusOK {
		t.Fatalf("administrator offboard with another active administrator = %d, want 200; body=%s", code, body)
	}
	member, err := h.store.GetTenantMember(t.Context(), h.tenant, "second-admin")
	if err != nil || member.Status != "active" {
		t.Fatalf("remaining administrator = %+v, err=%v", member, err)
	}
}

func TestServedMemberAuthorityRequiresAdministratorForSignInFallback(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-admin", []string{string(authz.Wildcard)})
	perms := authz.BuiltinRoles()["operator"].Permissions
	operatorScopes := make([]string, len(perms))
	for i, permission := range perms {
		operatorScopes[i] = string(permission)
	}
	operator := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-operator", operatorScopes)
	upsertMember(t, h.ts, admin, "sign-in-member", []string{"viewer"})
	code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/sign-in-member",
		operator, "member-sign-in-fallback", map[string]any{"roles": []string{}, "source": "manual"})
	if code != http.StatusForbidden {
		t.Fatalf("sign-in fallback without administrator authority = %d, want 403; body=%s", code, body)
	}
}

func TestServedMemberAuthorityAllowsHeldRolesForNewMember(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	perms := authz.BuiltinRoles()["operator"].Permissions
	operatorScopes := make([]string, len(perms))
	for i, permission := range perms {
		operatorScopes[i] = string(permission)
	}
	operator := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-operator", operatorScopes)
	code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/new-reader",
		operator, "member-new-reader", map[string]any{"roles": []string{"viewer"}, "source": "manual"})
	if code != http.StatusOK {
		t.Fatalf("new member with held role = %d, want 200; body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/members/unknown-subject/offboard",
		operator, "member-unknown-offboard", map[string]any{"reason": "removed"})
	if code != http.StatusForbidden {
		t.Fatalf("unknown member offboard = %d, want 403; body=%s", code, body)
	}
}

func TestServedMemberAuthorityPreservesConfiguredEmergencyAdministrator(t *testing.T) {
	svc := breakglass.NewAdminService(breakglass.AdminConfig{
		Enabled: true, TenantID: servedTestTenant,
		Params: crypto.Argon2idParams{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32},
	})
	if err := svc.SetPassword("recovery-admin", []byte("local-test-password")); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(deps *Deps) {
		deps.APIOptions = append(deps.APIOptions, api.WithBreakglassAdmin(svc))
	})
	admin := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "member-admin", []string{string(authz.Wildcard)})
	for _, test := range []struct {
		name, method, path string
		body               any
	}{
		{name: "offboard", method: http.MethodPost, path: "/api/v1/access/members/recovery-admin/offboard",
			body: map[string]string{"reason": "completed access review"}},
		{name: "replace", method: http.MethodPut, path: "/api/v1/access/members/recovery-admin",
			body: map[string]any{"roles": []string{"viewer"}, "source": "manual"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, body := doBearer(t, h.ts, test.method, test.path, admin, "member-emergency-"+test.name, test.body)
			if code != http.StatusForbidden {
				t.Fatalf("emergency administrator member change = %d, want 403; body=%s", code, body)
			}
		})
	}
}
