// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestServedOwnershipAssignmentIsTenantSafeReplayableAndAuthoritative proves
// that the ownership cockpit changes real lifecycle authority. The same bulk
// decision updates native identity rows, attribution, immutable history, and a
// cold rebuild; a stable retry key cannot append a second decision and a
// neighboring tenant cannot borrow either the owner or inventory identifiers.
func TestServedOwnershipAssignmentIsTenantSafeReplayableAndAuthoritative(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	const subject = "ownership-operator@example.test"
	token := seedScopedTokenSubject(t, h.store, h.tenant, subject,
		"owners:read", "owners:write", "identities:read", "identities:write", "nhi:read")

	oldOwnerID := servedCreateID(t, h, token, "ownership-old-owner", "/api/v1/owners", map[string]any{
		"kind": "team", "name": "Legacy platform", "application_id": "APP-OLD", "environment": "production",
	})
	newOwnerID := servedCreateID(t, h, token, "ownership-new-owner", "/api/v1/owners", map[string]any{
		"kind": "service", "name": "Platform Trust", "email": "platform-trust@example.test",
		"application_id": "APP-TRUST", "service": "credential-platform", "business_unit": "Engineering",
		"environment": "production", "escalation_chain": []string{"security-oncall@example.test"},
	})
	identityA := servedCreateID(t, h, token, "ownership-identity-a", "/api/v1/identities", map[string]any{
		"kind": "api_key", "name": "deployment key", "owner_id": oldOwnerID,
	})
	identityB := servedCreateID(t, h, token, "ownership-identity-b", "/api/v1/identities", map[string]any{
		"kind": "workload_identity", "name": "build client", "owner_id": oldOwnerID,
	})
	inventoryIDs := []string{"identity/" + identityB, "identity/" + identityA}
	request := map[string]any{
		"owner_id": newOwnerID, "inventory_ids": inventoryIDs,
		"reason": "Platform Trust owns production credential incident response",
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ownership/assignments", token,
		"ownership-bulk-handoff-1", request)
	if status != http.StatusOK {
		t.Fatalf("assign ownership = %d: %s", status, body)
	}
	firstResponse := append([]byte(nil), body...)
	var result struct {
		OwnerID    string   `json:"owner_id"`
		Assigned   []string `json:"assigned"`
		AssignedBy string   `json:"assigned_by"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode ownership assignment: %v (%s)", err, body)
	}
	if result.OwnerID != newOwnerID || result.AssignedBy != subject || len(result.Assigned) != 2 ||
		result.Assigned[0] >= result.Assigned[1] {
		t.Fatalf("ownership assignment lost owner, attribution, bulk membership, or canonical order: %+v", result)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ownership/assignments", token,
		"ownership-bulk-handoff-1", request)
	if status != http.StatusOK || string(body) != string(firstResponse) ||
		servedOwnershipAssignmentEventCount(t, h) != 1 {
		t.Fatalf("stable retry changed response or event count: status=%d body=%s events=%d",
			status, body, servedOwnershipAssignmentEventCount(t, h))
	}

	for _, identityID := range []string{identityA, identityB} {
		identity, err := h.store.GetIdentity(ctx, h.tenant, identityID)
		if err != nil || identity.OwnerID != newOwnerID {
			t.Fatalf("native identity owner for %s = %q err=%v, want %s", identityID, identity.OwnerID, err, newOwnerID)
		}
	}
	status, body = secretsReqKey(t, h, http.MethodGet, "/api/v1/ownership/attribution", token, "", nil)
	if status != http.StatusOK || strings.Count(string(body), `"attribution_source":"asset_override"`) != 2 ||
		strings.Count(string(body), `"id":"`+newOwnerID+`"`) != 2 ||
		strings.Count(string(body), `ownership.assignment:`) != 2 {
		t.Fatalf("served attribution does not expose both immutable overrides: status=%d body=%s", status, body)
	}

	assignments, err := h.store.ListOwnershipAssignments(ctx, h.tenant)
	if err != nil || len(assignments) != 2 || assignments[0].SourceEventID == "" {
		t.Fatalf("current assignment projection = %+v err=%v", assignments, err)
	}
	var immutable projections.OwnershipAssigned
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventOwnershipAssigned {
			return json.Unmarshal(event.Data, &immutable)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if immutable.Reason != request["reason"] || immutable.AssignedBy != subject || len(immutable.InventoryIDs) != 2 {
		t.Fatalf("immutable decision evidence = %+v", immutable)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ownership/assignments", token,
		"ownership-oversized-reason", map[string]any{
			"owner_id": newOwnerID, "inventory_ids": []string{"identity/" + identityA},
			"reason": strings.Repeat("r", projections.MaxOwnershipAssignmentReasonLength+1),
		})
	if status != http.StatusBadRequest || servedOwnershipAssignmentEventCount(t, h) != 1 {
		t.Fatalf("oversized decision was not rejected before event append: status=%d body=%s events=%d",
			status, body, servedOwnershipAssignmentEventCount(t, h))
	}

	const neighborTenant = "22222222-2222-2222-2222-222222222275"
	registerServedTenantID(t, h, neighborTenant, "Ownership neighbor")
	neighborToken := seedScopedTokenSubject(t, h.store, neighborTenant, "neighbor@example.test", "owners:read", "owners:write")
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ownership/assignments", neighborToken,
		"ownership-neighbor-borrow", request)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("neighbor borrowed owner/inventory authority: status=%d body=%s", status, body)
	}

	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold ownership-assignment rebuild: %v", err)
	}
	rebuiltAssignments, err := h.store.ListOwnershipAssignments(ctx, h.tenant)
	if err != nil || len(rebuiltAssignments) != 2 {
		t.Fatalf("rebuilt assignment projection = %+v err=%v", rebuiltAssignments, err)
	}
	for _, identityID := range []string{identityA, identityB} {
		identity, err := h.store.GetIdentity(ctx, h.tenant, identityID)
		if err != nil || identity.OwnerID != newOwnerID {
			t.Fatalf("rebuilt native owner for %s = %q err=%v, want %s", identityID, identity.OwnerID, err, newOwnerID)
		}
	}
}

func servedOwnershipAssignmentEventCount(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventOwnershipAssigned {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
