// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
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
	provisioner := seedServedAPIToken(t, ctx, h.store, h.tenant, "role-provisioner", []string{"access:read", "access:write", "access:role.assign"})
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
