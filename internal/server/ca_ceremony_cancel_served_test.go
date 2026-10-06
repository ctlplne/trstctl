// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestServedCACeremonyCancelIsTerminalAndAudited(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	opener := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ceremony-opener", []string{"issuers:write", "issuers:read"})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "distinct-custodian", []string{"issuers:write", "issuers:read"})
	readOnly := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "reader", []string{"issuers:read"})
	spec := map[string]any{"common_name": "cancelled root", "ttl_seconds": 31536000, "signature_algorithm": "ECDSA-P256"}
	ceremony := createCACeremony(t, h, opener, "create_root", "", spec, 2, "cancelled-root-ceremony")
	if ceremony.Status != "pending" || ceremony.Approvals != 0 {
		t.Fatalf("initial ceremony = %+v", ceremony)
	}
	path := "/api/v1/ca/ceremonies/" + ceremony.ID + "/cancel"
	if code, _ := doBearer(t, h.ts, http.MethodPost, path, readOnly, "readonly-cancel", map[string]any{"reason": "change window closed"}); code != http.StatusForbidden {
		t.Fatalf("read-only cancel = %d, want 403", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, path, opener, "blank-reason-cancel", map[string]any{"reason": " "}); code != http.StatusUnprocessableEntity {
		t.Fatalf("blank-reason cancel = %d, want 422", code)
	}
	code, body := doBearer(t, h.ts, http.MethodPost, path, opener, "exact-cancel", map[string]any{"reason": "change window closed"})
	if code != http.StatusOK {
		t.Fatalf("cancel = %d body=%s, want 200", code, body)
	}
	var closed struct {
		Status string `json:"status"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(body, &closed); err != nil || closed.ID != ceremony.ID || closed.Status != "cancelled" {
		t.Fatalf("cancel response = %+v, %v", closed, err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, path, opener, "exact-cancel", map[string]any{"reason": "change window closed"})
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"cancelled"`) {
		t.Fatalf("same-key replay = %d body=%s", code, body)
	}
	if n := servedEventCount(t, h, "ca.ceremony.cancelled"); n != 1 {
		t.Fatalf("cancel events = %d, want exactly 1", n)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, path, opener, "different-cancel", map[string]any{"reason": "change window closed"}); code != http.StatusConflict {
		t.Fatalf("different-key cancel of terminal ceremony = %d, want 409", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", approver, "approve-cancelled", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("approval after cancel = %d, want 409", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", opener, "create-cancelled-root", map[string]any{"ceremony_id": ceremony.ID, "spec": spec}); code != http.StatusConflict {
		t.Fatalf("root creation after cancel = %d, want 409", code)
	}
	readback, err := h.store.GetKeyCeremony(context.Background(), h.tenant, ceremony.ID)
	if err != nil || readback.Status != "cancelled" || readback.Approvals != 0 {
		t.Fatalf("terminal readback = %+v, %v", readback, err)
	}
	if _, err := h.store.GetKeyCeremony(context.Background(), "00000000-0000-4000-8000-000000000999", ceremony.ID); err == nil || err == store.ErrKeyCeremonyNotPending {
		t.Fatalf("cross-tenant ceremony read leaked: %v", err)
	}
}
