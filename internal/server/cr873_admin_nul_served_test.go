// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// Invalid free text is rejected before source publication on every covered
// tenant route, and the served runtime remains restartable.
func TestServedTextAdmissionRejectsInvalidMemberFields(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{})
	second := uuid.NewString()
	registerServedTenantID(t, h, second, "SWNUL victim tenant")
	adminScopes := []string{"access:write", "access:read", "access:role.assign"}
	for _, permission := range authz.BuiltinRoles()["viewer"].Permissions {
		adminScopes = append(adminScopes, string(permission))
	}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "swnul-admin", adminScopes...)

	// Fixtures (clean requests).
	if st, b := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/members/swnul-victim-member", admin, "swnul-fx-member",
		map[string]any{"display_name": "Clean Name", "email": "clean@example.test", "roles": []string{"viewer"}}); st != http.StatusOK {
		t.Fatalf("member fixture: %d %s", st, b)
	}
	var tok struct {
		ID string `json:"id"`
	}
	if st, b := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/api-tokens", admin, "swnul-fx-token",
		map[string]any{"subject": "swnul-admin", "scopes": []string{"access:read"}}); st != http.StatusCreated || json.Unmarshal(b, &tok) != nil || tok.ID == "" {
		t.Fatalf("token fixture: %d %s", st, b)
	}
	// Controls: clean free text is accepted.
	if st, b := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/roles/swnul-control", admin, "swnul-ctl-role",
		map[string]any{"description": "clean description", "permissions": []string{"access:read"}}); st != http.StatusOK {
		t.Fatalf("control role: %d %s", st, b)
	}

	type testCase struct {
		name, method, path, key string
		body                    any
	}
	cases := []testCase{
		{"custom-role description", http.MethodPut, "/api/v1/access/roles/swnul-invalid", "swnul-a1",
			map[string]any{"description": "bad\u0000desc", "permissions": []string{"access:read"}}},
		{"member upsert display_name", http.MethodPut, "/api/v1/access/members/swnul-member-2", "swnul-a2",
			map[string]any{"display_name": "bad\u0000name", "email": "m2@example.test", "roles": []string{"viewer"}}},
		{"api-token revoke reason", http.MethodDelete, "/api/v1/access/api-tokens/" + tok.ID, "swnul-a3",
			map[string]any{"reason": "bad\u0000reason"}},
		{"member offboard reason", http.MethodPost, "/api/v1/access/members/swnul-victim-member/offboard", "swnul-a4",
			map[string]any{"reason": "bad\u0000reason"}},
	}
	for _, a := range cases {
		before, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st, b := secretsReqKey(t, h, a.method, a.path, admin, a.key, a.body)
		after, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var types []string
		_ = h.log.Replay(ctx, before, func(e events.Event) error {
			if e.Sequence > before {
				types = append(types, e.Type)
			}
			return nil
		})
		t.Logf("SWNUL %-28s status=%d appended=%d types=%v body=%.160s", a.name, st, after-before, types, strings.TrimSpace(string(b)))
		if st != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", a.name, st)
		}
		if after != before {
			t.Errorf("%s: request retained %d event(s) %v", a.name, after-before, types)
		}
	}
	h.ts.Close()
	restarted, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, Protocols: config.Protocols{}})
	if err != nil {
		t.Errorf("restart Build failed after refused NUL requests: %v", err)
		return
	}
	cleanupServedServer(t, restarted)
}
