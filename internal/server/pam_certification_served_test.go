// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

// TestServedCertificationCampaignCertifiesAccountsAndApproversWithASignedResultA276:
// a campaign generated from brokered accounts lists each account (its
// owner, roles and template) and each approver list (a template's approvers
// and quorum, the approvers of access without a template, the emergency
// responders). Its result is refused while items wait; once a distinct
// reviewer certifies the approver lists and accounts — and does not certify
// one account, which is disabled and read back — the result is signed with
// the audit key and the signature verifies over exactly the result. The
// periodic certification starts the next campaign only once the interval
// has passed.
func TestServedCertificationCampaignCertifiesAccountsAndApproversWithASignedResultA276(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	ctx := context.Background()
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a276-cert-admin", "access:read", "access:write", "access:targets.write", "access:role.assign",
		"owners:read", "owners:write", "secrets:read", "secrets:write", "graph:read")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "a276-cert-reviewer", "access:read", "access:write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", admin, "a276c-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", admin, "a276c-template",
		map[string]any{"name": "orders-maintenance", "reason": "Orders maintenance", "required_approvals": 2, "max_ttl_seconds": 120})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
		t.Fatalf("template: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/folders/orders", admin, "a276c-folder",
		map[string]any{"template_id": template.ID, "description": "Orders accounts"}); status != http.StatusOK {
		t.Fatalf("folder: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", admin, "a276c-register",
		map[string]any{"id": "orders-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole, "folder": "orders"}); status != http.StatusCreated {
		t.Fatalf("register: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/owners", admin, "a276c-owner", map[string]any{"kind": "team", "name": "Orders platform"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &owner) != nil {
		t.Fatalf("owner: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/ownership/assignments", admin, "a276c-assign",
		map[string]any{"owner_id": owner.ID, "inventory_ids": []string{"pam-account/postgres/orders-vault"}, "reason": "orders platform"}); status != http.StatusOK {
		t.Fatalf("assign: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/members/"+url.PathEscape("erin@example.test"), admin, "a276c-approver",
		map[string]any{"display_name": "Erin", "email": "erin@example.test", "roles": []string{"operator"}}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("approver member: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/emergency/responders", admin, "a276c-responders",
		map[string]any{"subjects": []string{"oncall@example.test"}}); status != http.StatusOK {
		t.Fatalf("responders: %d %s", status, body)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/reviews/generate", admin, "a276c-generate",
		map[string]any{"name": "Q4 privileged account certification", "source": "pam_accounts"})
	var generated struct {
		Campaign struct {
			ID    string `json:"id"`
			Scope string `json:"scope"`
			Items []struct {
				ItemID      string `json:"item_id"`
				NHIID       string `json:"nhi_id"`
				NHIKind     string `json:"nhi_kind"`
				OwnerRef    string `json:"owner_ref"`
				Entitlement string `json:"entitlement"`
			} `json:"items"`
		} `json:"campaign"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &generated) != nil || generated.Campaign.Scope != "pam_accounts" {
		t.Fatalf("generate: %d %s", status, body)
	}
	items := map[string]int{}
	for i, it := range generated.Campaign.Items {
		items[it.NHIID] = i
	}
	account, ok := items["pam-account:postgres/orders-vault"]
	tplApprovers, ok2 := items["pam-approvers:"+template.ID]
	_, ok3 := items["pam-approvers:default"]
	responders, ok4 := items["pam-responders:emergency"]
	if !ok || !ok2 || !ok3 || !ok4 {
		t.Fatalf("the campaign's items: %+v", generated.Campaign.Items)
	}
	if it := generated.Campaign.Items[account]; it.NHIKind != "privileged_account" || it.OwnerRef != owner.ID ||
		!strings.Contains(it.Entitlement, "template orders-maintenance revision 1: 2 approvals") {
		t.Fatalf("the account item: %+v", it)
	}
	if it := generated.Campaign.Items[tplApprovers]; it.NHIKind != "approver_list" || !strings.Contains(it.Entitlement, "2 distinct approvals from:") ||
		!strings.Contains(it.Entitlement, "erin@example.test") {
		t.Fatalf("the template's approver list: %+v", it)
	}
	if it := generated.Campaign.Items[responders]; !strings.Contains(it.Entitlement, "oncall@example.test") {
		t.Fatalf("the responders item: %+v", it)
	}
	result := func() (int, api.CertificationResult) {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/reviews/"+generated.Campaign.ID+"/result", admin, nil)
		var out api.CertificationResult
		if status == http.StatusOK && json.Unmarshal(body, &out) != nil {
			t.Fatalf("result: %s", body)
		}
		return status, out
	}
	if status, _ := result(); status != http.StatusConflict {
		t.Fatalf("a result before every item is decided = %d", status)
	}
	for i, it := range generated.Campaign.Items {
		decision, reason := "certified", "still needed and correctly approved"
		if i == account {
			decision, reason = "revoked", "the orders ledger moved; retire the account"
		}
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/reviews/"+generated.Campaign.ID+"/items/"+it.ItemID+"/decision",
			reviewer, "a276c-decide-"+it.ItemID, map[string]any{"decision": decision, "reason": reason}); status != http.StatusOK {
			t.Fatalf("decide %s: %d %s", it.NHIID, status, body)
		}
	}
	a201Await(t, "the revoked account reads disabled", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/targets/postgres/orders-vault", admin, nil)
		var tg api.PAMTarget
		return status == http.StatusOK && json.Unmarshal(body, &tg) == nil && !tg.Enabled
	})
	status, signed := result()
	if status != http.StatusOK || signed.Artifact != "access-certification-result" || signed.Signature == "" {
		t.Fatalf("the signed result = %d %+v", status, signed)
	}
	payload, err := f.auditKey.JWKS().VerifyArtifact(signed.Signature, "access-certification-result")
	if err != nil || !bytes.Equal(bytes.TrimSpace(payload), bytes.TrimSpace(signed.Result)) {
		t.Fatalf("the audit key's signature does not cover the result: %v", err)
	}
	var decoded struct {
		Scope     string `json:"scope"`
		Certified int    `json:"certified"`
		Revoked   int    `json:"revoked"`
		Items     []struct {
			NHIID      string `json:"nhi_id"`
			Status     string `json:"status"`
			DecisionBy string `json:"decision_by"`
		} `json:"items"`
	}
	if json.Unmarshal(signed.Result, &decoded) != nil || decoded.Scope != "pam_accounts" || decoded.Revoked != 1 || decoded.Certified != len(generated.Campaign.Items)-1 {
		t.Fatalf("the signed result's content: %s", signed.Result)
	}
	for _, it := range decoded.Items {
		if it.DecisionBy != "a276-cert-reviewer" || (it.NHIID == "pam-account:postgres/orders-vault") != (it.Status == "revoked") {
			t.Fatalf("a signed decision: %+v", it)
		}
	}

	// Periodic certification: not due within the interval, due after it.
	h.srv.pam.certificationInterval = time.Hour
	if started, err := h.srv.pam.certifyTenantIfDue(ctx, h.tenant, time.Now().UTC()); err != nil || started {
		t.Fatalf("a certification started within the interval: %v %v", started, err)
	}
	if started, err := h.srv.pam.certifyTenantIfDue(ctx, h.tenant, time.Now().UTC().Add(2*time.Hour)); err != nil || !started {
		t.Fatalf("no certification started after the interval: %v %v", started, err)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/reviews", admin, nil)
	if status != http.StatusOK || strings.Count(string(body), `"scope":"pam_accounts"`) != 2 || !strings.Contains(string(body), `"requested_by":"trstctl:pam-certification"`) {
		t.Fatalf("the periodic campaign: %d %s", status, body)
	}
}
