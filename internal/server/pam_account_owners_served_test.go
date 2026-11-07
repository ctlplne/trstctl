// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedBrokeredAccountsAreInventoriedWithOwnersA276: every brokered
// account — a privileged access target, configured or registered — is an
// NHI inventory record (pam-account/<type>/<id>, kind privileged_account),
// so the ownership assignment that names any record's owner names its owner
// too; the target reads its owner back, and another tenant can neither see
// the record nor assign it.
func TestServedBrokeredAccountsAreInventoriedWithOwnersA276(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, MaxTTL: time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a276-registrar", "access:read", "access:targets.write")
	steward := seedScopedTokenSubject(t, h.store, h.tenant, "a276-steward", "owners:read", "owners:write", "identities:read", "nhi:read")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", registrar, "a276-register",
		map[string]any{"id": "orders-pg", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"}}); status != http.StatusCreated {
		t.Fatalf("register: %d %s", status, body)
	}
	const record = "pam-account/postgres/orders-pg"
	inventory := func(token string) map[string]map[string]any {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/inventory", token, nil)
		var out struct {
			Items         []map[string]any `json:"items"`
			RecordSummary map[string]any   `json:"record_summary"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("inventory: %d %s", status, body)
		}
		byID := map[string]map[string]any{}
		for _, item := range out.Items {
			byID[item["id"].(string)] = item
		}
		if out.RecordSummary["privileged_account_records"] == nil {
			t.Fatalf("the record summary does not count brokered accounts: %v", out.RecordSummary)
		}
		return byID
	}
	item := inventory(steward)[record]
	if item == nil || item["kind"] != "privileged_account" || item["source"] != "pam_target" || item["status"] != "active" || item["owner_id"] != nil {
		t.Fatalf("the brokered account's inventory record: %+v", item)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", steward, "a276-owner", map[string]any{"kind": "team", "name": "Orders platform", "email": "orders@example.test"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &owner) != nil || owner.ID == "" {
		t.Fatalf("create owner: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ownership/assignments", steward, "a276-assign",
		map[string]any{"owner_id": owner.ID, "inventory_ids": []string{record}, "reason": "orders platform runs this database"}); status != http.StatusOK {
		t.Fatalf("assign: %d %s", status, body)
	}
	if got := inventory(steward)[record]; got["owner_id"] != owner.ID {
		t.Fatalf("the inventory record's owner: %+v", got)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/access/targets/postgres/orders-pg", registrar, nil)
	var target api.PAMTarget
	if status != http.StatusOK || json.Unmarshal(body, &target) != nil || target.OwnerID != owner.ID {
		t.Fatalf("the target's owner: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/access/targets", registrar, nil)
	var listed struct {
		Items []api.PAMTarget `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) == 0 {
		t.Fatalf("list targets: %d %s", status, body)
	}
	for _, tgt := range listed.Items {
		if tgt.ID == "orders-pg" && tgt.OwnerID != owner.ID {
			t.Fatalf("the listed target's owner: %+v", tgt)
		}
	}

	other := "33333333-3333-4333-8333-333333333333"
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: other, Name: "A276 isolation"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, other, "a276-foreign", "owners:read", "owners:write", "identities:read", "nhi:read")
	if inventory(foreign)[record] != nil {
		t.Fatal("another tenant's inventory lists the brokered account")
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", foreign, "a276-foreign-owner", map[string]any{"kind": "team", "name": "Elsewhere"})
	var foreignOwner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &foreignOwner) != nil {
		t.Fatalf("foreign owner: %d %s", status, body)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/ownership/assignments", foreign, "a276-foreign-assign",
		map[string]any{"owner_id": foreignOwner.ID, "inventory_ids": []string{record}, "reason": "not ours"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("another tenant assigned the brokered account: %d", status)
	}
}
