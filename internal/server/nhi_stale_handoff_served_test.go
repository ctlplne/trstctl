// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type staleRow struct {
	InventoryID  string   `json:"inventory_id"`
	OwnerID      string   `json:"owner_id"`
	OwnerStatus  string   `json:"owner_status"`
	FindingTypes []string `json:"finding_types"`
}

func staleRowFor(t *testing.T, h *servedHarness, token, inventoryID string) (staleRow, bool) {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/stale", token, nil)
	var posture struct {
		Findings []staleRow `json:"findings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
		t.Fatalf("stale posture = %d %s", status, body)
	}
	for _, row := range posture.Findings {
		if row.InventoryID == inventoryID {
			return row, true
		}
	}
	return staleRow{}, false
}

// A101: a stale, orphaned NHI found by discovery is handed to a new
// accountable owner in one step. The handoff names the previous owner status,
// the inventory honors the assignment so the posture no longer reports the
// record orphaned, the new owner is notified on the ownership channel, and a
// retry of the same request changes nothing.
func TestServedStaleNHIHandoffAssignsAndNotifies(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	const findingID = "22222222-2222-2222-2222-22222222c003"
	old := time.Now().UTC().Add(-400 * 24 * time.Hour)
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant,
		"22222222-2222-2222-2222-22222222c001", "22222222-2222-2222-2222-22222222c002", findingID,
		old, map[string]any{"last_used_at": old.Format(time.RFC3339)})
	inventoryID := "finding/" + findingID
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")
	writer := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write")
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerUser,
		Name: "Platform team lead", Email: "platform-lead@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	before, ok := staleRowFor(t, h, reader, inventoryID)
	if !ok || before.OwnerStatus != "orphaned" || !containsString(before.FindingTypes, "orphaned_nhi") {
		t.Fatalf("before the handoff: row=%+v found=%v; want an orphaned stale NHI", before, ok)
	}

	request := map[string]any{"owner_id": owner.ID, "inventory_ids": []string{inventoryID}, "reason": "previous owner left the company"}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/stale/handoff", writer, "stale-handoff-1", request)
	var handoff struct {
		OwnerID      string `json:"owner_id"`
		NoticeQueued bool   `json:"notice_queued"`
		Items        []struct {
			InventoryID     string `json:"inventory_id"`
			FromOwnerStatus string `json:"from_owner_status"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &handoff) != nil || handoff.OwnerID != owner.ID || !handoff.NoticeQueued ||
		len(handoff.Items) != 1 || handoff.Items[0].InventoryID != inventoryID || handoff.Items[0].FromOwnerStatus != "orphaned" {
		t.Fatalf("handoff = %d %s", status, body)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/stale/handoff", writer, "stale-handoff-1", request); status != http.StatusOK || !bytes.Equal(replay, body) {
		t.Fatalf("replay = %d %s", status, replay)
	}

	after, ok := staleRowFor(t, h, reader, inventoryID)
	if !ok || after.OwnerID != owner.ID || after.OwnerStatus != "owned" || containsString(after.FindingTypes, "orphaned_nhi") ||
		!containsString(after.FindingTypes, "dormant_activity") {
		t.Fatalf("after the handoff: row=%+v found=%v; want it owned and still dormant", after, ok)
	}

	var notices int
	var payload []byte
	rows, err := h.store.SystemPool().Query(t.Context(), `SELECT payload FROM outbox
		WHERE tenant_id = $1 AND destination = 'notification.ownership' AND idempotency_key LIKE 'ownership-handoff:%'`, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		notices++
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
	}
	rows.Close()
	if notices != 1 || !bytes.Contains(payload, []byte(`"ownership.handoff"`)) || !bytes.Contains(payload, []byte("platform-lead@example.test")) ||
		!bytes.Contains(payload, []byte(inventoryID)) {
		t.Fatalf("handoff notices = %d payload=%s", notices, payload)
	}

	// Only stale rows are handed off, and never to the owner they already have.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/stale/handoff", writer, "stale-handoff-2",
		map[string]any{"owner_id": owner.ID, "inventory_ids": []string{"finding/22222222-2222-2222-2222-22222222ffff"}, "reason": "x"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("handoff of a non-stale record = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/stale/handoff", writer, "stale-handoff-3", request); status != http.StatusConflict {
		t.Fatalf("handoff to the current owner = %d %s", status, body)
	}
}
