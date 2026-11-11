// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestServedProjectAdminsManageTheirOwnProjectsMembershipA235L1 is A235-L1: a
// member holding a project's admin role grants and revokes that project's
// members without access:write, within its own grant — never another
// project's, never an environment it does not hold, never a member whose
// grant reaches past its own — and the project view tells each caller what
// it may manage. A project admin acts under secrets:write: holding only
// secrets:read it manages nothing. access:write keeps full control, even
// alone, and a secrets:write non-member still cannot grant itself anything.
func TestServedProjectAdminsManageTheirOwnProjectsMembershipA235L1(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A235-L1 project delegation tenant")
	tenantAdmin := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-tenant-admin", "secrets:read", "secrets:write", "access:write")
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-alice", "secrets:read", "secrets:write")
	carol := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-carol", "secrets:read", "secrets:write")
	dave := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-dave", "secrets:read", "secrets:write")
	eve := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-eve", "secrets:read", "secrets:write")
	// iam holds access:write alone; frank, the project's admin, holds only
	// secrets:read.
	iam := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-iam", "access:write")
	frank := seedScopedTokenSubject(t, h.store, h.tenant, "a235l1-frank", "secrets:read")

	call := func(tok, method, path string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReq(t, h, method, path, tok, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	member := func(path, subject string) string { return path + "/members/" + subject }
	const pay = "/api/v1/secrets/projects/pay235"
	envs := []any{map[string]any{"slug": "dev"}, map[string]any{"slug": "stage", "restricted": true}, map[string]any{"slug": "prod", "restricted": true}}
	call(tenantAdmin, http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "pay235", "environments": envs}, http.StatusCreated)
	call(tenantAdmin, http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "bill235", "environments": envs}, http.StatusCreated)
	call(tenantAdmin, http.MethodPut, member(pay, "a235l1-alice"), map[string]any{"role": "admin", "environments": []string{"stage"}}, http.StatusOK)
	call(tenantAdmin, http.MethodPut, member(pay, "a235l1-carol"), map[string]any{"role": "admin"}, http.StatusOK)
	call(tenantAdmin, http.MethodPut, member(pay, "a235l1-dave"), map[string]any{"role": "developer", "environments": []string{"stage"}}, http.StatusOK)
	call(tenantAdmin, http.MethodPut, member(pay, "a235l1-frank"), map[string]any{"role": "admin"}, http.StatusOK)

	// alice, admin of pay235 for stage, manages stage there.
	call(alice, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "developer", "environments": []string{"stage"}}, http.StatusOK)
	call(alice, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "viewer", "environments": []string{"prod"}}, http.StatusForbidden)
	call(alice, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "viewer"}, http.StatusForbidden)
	call(alice, http.MethodPut, member(pay, "a235l1-carol"), map[string]any{"role": "viewer", "environments": []string{"stage"}}, http.StatusForbidden)
	call(alice, http.MethodDelete, member(pay, "a235l1-carol"), nil, http.StatusForbidden)
	call(alice, http.MethodPut, member("/api/v1/secrets/projects/bill235", "a235l1-bob"), map[string]any{"role": "viewer", "environments": []string{"stage"}}, http.StatusForbidden)
	call(alice, http.MethodPut, member(pay, "a235l1-alice"), map[string]any{"role": "admin", "environments": []string{"stage", "prod"}}, http.StatusForbidden)
	call(alice, http.MethodPost, pay+"/environments", map[string]any{"slug": "qa"}, http.StatusForbidden)

	// carol, admin for every environment, manages all of pay235.
	call(carol, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "viewer", "environments": []string{"stage", "prod"}}, http.StatusOK)
	call(alice, http.MethodDelete, member(pay, "a235l1-bob"), nil, http.StatusForbidden) // bob now reaches prod
	call(carol, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "developer", "environments": []string{"stage"}}, http.StatusOK)
	call(alice, http.MethodDelete, member(pay, "a235l1-bob"), nil, http.StatusOK)

	// A developer, a secrets:write non-member, and an admin holding only
	// secrets:read manage nothing.
	call(dave, http.MethodPut, member(pay, "a235l1-dave"), map[string]any{"role": "admin", "environments": []string{"stage"}}, http.StatusForbidden)
	call(eve, http.MethodPut, member(pay, "a235l1-eve"), map[string]any{"role": "admin"}, http.StatusForbidden)
	call(eve, http.MethodDelete, member(pay, "a235l1-dave"), nil, http.StatusForbidden)
	call(frank, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "viewer", "environments": []string{"stage"}}, http.StatusForbidden)
	call(frank, http.MethodDelete, member(pay, "a235l1-dave"), nil, http.StatusForbidden)

	// access:write alone still manages any project's membership in full.
	call(iam, http.MethodPut, member("/api/v1/secrets/projects/bill235", "a235l1-gina"), map[string]any{"role": "admin", "environments": []string{"prod"}}, http.StatusOK)
	call(iam, http.MethodDelete, member("/api/v1/secrets/projects/bill235", "a235l1-gina"), nil, http.StatusOK)

	// The project view says what each caller may manage.
	type view struct {
		CanManageMembers       bool     `json:"can_manage_members"`
		ManageableEnvironments []string `json:"manageable_environments"`
		Members                []struct {
			Subject string `json:"subject"`
		} `json:"members"`
	}
	read := func(tok string) view {
		t.Helper()
		var v view
		if err := json.Unmarshal(call(tok, http.MethodGet, pay, nil, http.StatusOK), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := read(alice); !v.CanManageMembers || !slices.Equal(v.ManageableEnvironments, []string{"stage"}) {
		t.Fatalf("alice's view = %+v, want manage within stage", v)
	}
	if v := read(carol); !v.CanManageMembers || len(v.ManageableEnvironments) != 0 {
		t.Fatalf("carol's view = %+v, want manage every environment", v)
	}
	if v := read(dave); v.CanManageMembers {
		t.Fatalf("dave's view = %+v, want no member management", v)
	}
	if v := read(frank); v.CanManageMembers {
		t.Fatalf("frank's view = %+v, want no member management without secrets:write", v)
	}
	if v := read(tenantAdmin); !v.CanManageMembers || len(v.ManageableEnvironments) != 0 {
		t.Fatalf("the tenant admin's view = %+v", v)
	}
	for _, m := range read(tenantAdmin).Members {
		if m.Subject == "a235l1-bob" || m.Subject == "a235l1-eve" {
			t.Fatalf("membership after the refusals and the revoke holds %s", m.Subject)
		}
	}
	// access:write keeps full control.
	call(tenantAdmin, http.MethodPut, member(pay, "a235l1-bob"), map[string]any{"role": "viewer", "environments": []string{"prod"}}, http.StatusOK)
	call(tenantAdmin, http.MethodDelete, member(pay, "a235l1-carol"), nil, http.StatusOK)
	t.Log("A235L1_PROJECT_ADMIN_DELEGATION_OK")
}
