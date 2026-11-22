// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// F266: access:role.assign lets a caller hand out roles, but only a caller that
// holds every permission ("*") may grant a role that holds every permission.
// Otherwise an operator, or a stolen operator token, can create administrators.
func TestServedOnlyAdministratorsGrantTheAdminRole(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	var operatorScopes []string
	for _, p := range authz.BuiltinRoles()["operator"].Permissions {
		operatorScopes = append(operatorScopes, string(p))
	}
	provisionerScopes := []string{"access:write", "access:role.assign"}
	for _, p := range authz.BuiltinRoles()["viewer"].Permissions {
		provisionerScopes = append(provisionerScopes, string(p))
	}
	provisioner := seedServedAPIToken(t, ctx, h.store, h.tenant, "role-provisioner", provisionerScopes)
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "operator-grantor", operatorScopes)
	administrator := seedServedAPIToken(t, ctx, h.store, h.tenant, "tenant-admin", []string{"*"})
	deniedBefore := countRoleAssignDenialsF266(t, h)

	for _, tc := range []struct {
		name    string
		token   string
		subject string
		roles   []string
		want    int
	}{
		{"provisioning token cannot create an admin", provisioner, "would-be-admin-1", []string{"admin"}, http.StatusForbidden},
		{"operator cannot create an admin", operator, "would-be-admin-2", []string{"admin"}, http.StatusForbidden},
		{"operator cannot add admin beside another role", operator, "would-be-admin-3", []string{"viewer", "admin"}, http.StatusForbidden},
		{"provisioning token still adds a reader", provisioner, "team-reader", []string{"viewer"}, http.StatusOK},
		{"operator still grants operator", operator, "team-operator", []string{"operator"}, http.StatusOK},
		{"administrator creates an admin", administrator, "second-admin", []string{"admin"}, http.StatusOK},
	} {
		code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/"+tc.subject, tc.token, "f266-"+tc.subject,
			map[string]any{"display_name": tc.subject, "roles": tc.roles, "source": "manual"})
		if code != tc.want {
			t.Errorf("%s: PUT member %s roles %v = %d, want %d; body=%s", tc.name, tc.subject, tc.roles, code, tc.want, body)
			continue
		}
		if tc.want == http.StatusForbidden && !bytes.Contains(body, []byte("admin")) {
			t.Errorf("%s: refusal does not say why: %s", tc.name, body)
		}
	}

	code, listed := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/members?limit=100", administrator, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list members = %d body=%s", code, listed)
	}
	var page struct {
		Items []struct {
			Subject string   `json:"subject"`
			Roles   []string `json:"roles"`
		} `json:"items"`
	}
	if err := json.Unmarshal(listed, &page); err != nil {
		t.Fatalf("decode members: %v body=%s", err, listed)
	}
	for _, m := range page.Items {
		switch m.Subject {
		case "would-be-admin-1", "would-be-admin-2", "would-be-admin-3":
			t.Errorf("refused grant still created member %s with roles %v", m.Subject, m.Roles)
		}
	}
	if got := countRoleAssignDenialsF266(t, h) - deniedBefore; got != 3 {
		t.Errorf("recorded role-assignment denials = %d, want 3 (one per refused admin grant)", got)
	}
}

// CR-091: a missing or null roles field must never turn a member's restricted
// role set into an empty set, which would restore the OIDC sign-in default.
func TestServedMemberUpsertRequiresExplicitRolesForEveryEffect(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	admin := seedServedAPIToken(t, ctx, h.store, h.tenant, "cr091-admin", []string{"*"})
	writer := seedServedAPIToken(t, ctx, h.store, h.tenant, "cr091-writer", []string{"access:read", "access:write"})
	self := seedServedAPIToken(t, ctx, h.store, h.tenant, "cr091-member", []string{"access:read", "access:write"})
	path := "/api/v1/access/members/cr091-member"
	if code, body := doBearer(t, h.ts, http.MethodPut, path, admin, "cr091-seed",
		map[string]any{"roles": []string{"operator"}, "display_name": "restricted"}); code != http.StatusOK {
		t.Fatalf("seed restricted member = HTTP %d %s", code, body)
	}
	for _, tc := range []struct {
		name  string
		token string
		body  map[string]any
	}{
		{"self omits roles", self, map[string]any{"display_name": "self edited"}},
		{"writer omits roles", writer, map[string]any{"display_name": "writer edited"}},
		{"writer sends null roles", writer, map[string]any{"roles": nil, "display_name": "null edited"}},
		{"admin omits roles", admin, map[string]any{"display_name": "admin edited"}},
	} {
		code, body := doBearer(t, h.ts, http.MethodPut, path, tc.token, "cr091-"+tc.name, tc.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s = HTTP %d %s, want 400", tc.name, code, body)
		}
		member, err := h.store.GetTenantMember(ctx, h.tenant, "cr091-member")
		if err != nil || !slices.Equal(member.Roles, []string{"operator"}) {
			t.Fatalf("%s changed stored roles to %v: %v", tc.name, member.Roles, err)
		}
	}
	if code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/cr091-new", writer,
		"cr091-new-omitted", map[string]any{"display_name": "new"}); code != http.StatusBadRequest {
		t.Errorf("new member with omitted roles = HTTP %d %s, want 400", code, body)
	}
	deniedBefore := countRoleAssignDenialsF266(t, h)
	if code, body := doBearer(t, h.ts, http.MethodPut, path, writer, "cr091-clear-denied",
		map[string]any{"roles": []string{}, "display_name": "attempted clear"}); code != http.StatusForbidden {
		t.Errorf("writer explicitly cleared roles = HTTP %d %s, want 403", code, body)
	}
	if got := countRoleAssignDenialsF266(t, h) - deniedBefore; got != 1 {
		t.Errorf("explicit clear recorded %d role-assignment denials, want 1", got)
	}
	member, err := h.store.GetTenantMember(ctx, h.tenant, "cr091-member")
	if err != nil || !slices.Equal(member.Roles, []string{"operator"}) {
		t.Fatalf("denied clear changed stored roles to %v: %v", member.Roles, err)
	}
	if code, body := doBearer(t, h.ts, http.MethodPut, path, admin, "cr091-clear-allowed",
		map[string]any{"roles": []string{}, "display_name": "approved clear"}); code != http.StatusOK {
		t.Fatalf("administrator explicitly cleared roles = HTTP %d %s", code, body)
	}
	member, err = h.store.GetTenantMember(ctx, h.tenant, "cr091-member")
	if err != nil || len(member.Roles) != 0 {
		t.Fatalf("approved clear retained roles %v: %v", member.Roles, err)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, path+"/offboard", admin, "cr091-offboard",
		map[string]any{"reason": "role boundary regression"}); code != http.StatusOK {
		t.Fatalf("offboard member = HTTP %d %s", code, body)
	}
	deniedBefore = countRoleAssignDenialsF266(t, h)
	if code, body := doBearer(t, h.ts, http.MethodPut, path, writer, "cr091-rehire-denied",
		map[string]any{"roles": []string{"viewer"}}); code != http.StatusForbidden {
		t.Errorf("writer rehired member with roles = HTTP %d %s, want 403", code, body)
	}
	if got := countRoleAssignDenialsF266(t, h) - deniedBefore; got != 1 {
		t.Errorf("unauthorized rehire recorded %d role-assignment denials, want 1", got)
	}
	if code, body := doBearer(t, h.ts, http.MethodPut, path, admin, "cr091-rehire-allowed",
		map[string]any{"roles": []string{"viewer"}}); code != http.StatusOK {
		t.Fatalf("administrator rehired member with explicit roles = HTTP %d %s", code, body)
	}
}

func TestServedBuiltinRoleGrantRefusalIsRecordedCR023(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	var scopes []string
	for _, p := range authz.BuiltinRoles()["operator"].Permissions {
		scopes = append(scopes, string(p))
	}
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cr023-operator", scopes)
	deniedBefore := countRoleAssignDenialsF266(t, h)
	if code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/cr023-auditor", operator,
		"cr023-auditor", map[string]any{"roles": []string{"auditor"}}); code != http.StatusForbidden || !bytes.Contains(body, []byte(string(authz.AuditRead))) {
		t.Fatalf("operator granted auditor without audit:read: HTTP %d %s", code, body)
	}
	if got := countRoleAssignDenialsF266(t, h) - deniedBefore; got != 1 {
		t.Fatalf("built-in grant refusal recorded %d role decisions, want 1", got)
	}
	if code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/cr023-peer", operator,
		"cr023-peer", map[string]any{"roles": []string{"operator"}}); code != http.StatusOK {
		t.Fatalf("operator could not grant permissions it holds: HTTP %d %s", code, body)
	}
}

func countRoleAssignDenialsF266(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type != orchestrator.EventAuthzDecision || e.TenantID != h.tenant {
			return nil
		}
		var d orchestrator.AuthzDecision
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return err
		}
		if d.Permission == string(authz.AccessRoleAssign) && d.Decision == "deny" {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return count
}
