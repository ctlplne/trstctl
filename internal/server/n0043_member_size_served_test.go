// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestN0043ServedMemberSizeRefusalsLeaveNoPendingCommands(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "member size admission")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "member-size-admin", "*")
	status, body := secretsReqKey(t, h, http.MethodPut,
		"/api/v1/access/members/oversized-member", admin, "n0043-upsert", map[string]any{
			"display_name": strings.Repeat("<", 150000), "roles": []string{},
		})
	if status != http.StatusBadRequest {
		t.Fatalf("oversized member status=%d body=%s, want 400", status, body)
	}
	if pending, err := h.store.ListPendingTenantMemberUpsertCommands(t.Context(), h.tenant, 10); err != nil || len(pending) != 0 {
		t.Fatalf("oversized served upsert left %d pending commands: %v", len(pending), err)
	}
	status, body = secretsReqKey(t, h, http.MethodPut,
		"/api/v1/access/members/ready-member", admin, "n0043-ready", map[string]any{
			"display_name": "ready", "roles": []string{},
		})
	if status != http.StatusOK {
		t.Fatalf("create bounded member status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/access/members/ready-member/offboard", admin, "n0043-offboard", map[string]any{
			"reason": strings.Repeat("<", 150000),
		})
	if status != http.StatusBadRequest {
		t.Fatalf("oversized offboard status=%d body=%s, want 400", status, body)
	}
	if pending, err := h.store.ListPendingTenantMemberOffboardCommands(t.Context(), h.tenant, 10); err != nil || len(pending) != 0 {
		t.Fatalf("oversized served offboard left %d pending commands: %v", len(pending), err)
	}
}
