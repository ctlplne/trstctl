// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

const nhiPostureAutomationModule = policy.BaseModule + `
nhi_posture contains {"rule": "dormant-managed-revoke", "severity": "high", "reason": "dormant managed NHIs are revoked", "remediation": "revoke"} if {
	input.action == "nhi_posture"
	input.nhi.managed
	"dormant_activity" in input.nhi.finding_types
}

nhi_posture contains {"rule": "unused-scopes-trim", "severity": "medium", "reason": "unused grants are removed", "remediation": "right_size"} if {
	input.action == "nhi_posture"
	count(input.nhi.unused_scopes) > 0
}

nhi_posture contains {"rule": "static-watch", "reason": "reported only", "remediation": "rotate_everything"} if {
	input.action == "nhi_posture"
	input.nhi.kind == "api_key"
	"dormant_activity" in input.nhi.finding_types
}
`

type nhiPostureAutomationPlan struct {
	PolicyModuleSHA256 string `json:"policy_module_sha256"`
	PolicyEvaluated    int    `json:"policy_evaluated"`
	Summary            struct {
		Violations    int `json:"violations"`
		Revoke        int `json:"revoke"`
		RightSize     int `json:"right_size"`
		ReportOnly    int `json:"report_only"`
		NotApplicable int `json:"not_applicable"`
	} `json:"summary"`
	Items []struct {
		InventoryID string `json:"inventory_id"`
		Rule        string `json:"rule"`
		Remediation string `json:"remediation"`
		Action      string `json:"action"`
		LastRun     *struct {
			PlaybookID string `json:"playbook_id"`
			Status     string `json:"status"`
		} `json:"last_run"`
	} `json:"items"`
}

// nhiPostureAutomationFixture seeds a dormant managed API key and an
// over-privileged managed service account, then activates the tenant module
// whose nhi_posture rules ask to revoke the first and right-size the second.
func nhiPostureAutomationFixture(t *testing.T, opts ...func(*Deps)) (*servedHarness, string, string, string) {
	t.Helper()
	h := newOperatingServedHarness(t, config.Protocols{}, append([]func(*Deps){func(d *Deps) { d.EnablePolicyGate = true }}, opts...)...)
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerService, Name: "payments", Email: "payments@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	seed := func(id, kind, name string, attrs map[string]any) string {
		raw, err := json.Marshal(attrs)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.store.UpsertIdentity(t.Context(), store.Identity{ID: id, TenantID: h.tenant, Kind: store.IdentityKind(kind),
			Name: name, OwnerID: owner.ID, Status: "deployed", Attributes: raw}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	dormant := seed("11111111-1111-1111-1111-1111111a1001", "api_key", "legacy-batch-key", map[string]any{
		"last_used_at": time.Now().UTC().Add(-400 * 24 * time.Hour).Format(time.RFC3339),
	})
	wide := seed("11111111-1111-1111-1111-1111111a1002", "service_account", "payments-bot", map[string]any{
		"granted_scopes": []string{"secrets:read", "secrets:write", "admin:*"},
		"used_scopes":    []string{"secrets:read"},
		"last_used_at":   time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
	})
	author := seedScopedTokenSubject(t, h.store, h.tenant, "nhi-posture-author@example.test", "policy:read", "policy:write")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions", author, "a100-policy-create", map[string]any{
		"kind": "lifecycle", "description": "Act on NHI posture", "change_ref": "github:security/nhi-posture#1",
		"evidence_refs": []string{"pr:nhi-posture-1"}, "module": nhiPostureAutomationModule,
	})
	var created struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ID == "" {
		t.Fatalf("create NHI posture policy = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions/"+created.ID+"/activate", author, "a100-policy-activate",
		map[string]any{"reason": "NHI posture rules reviewed", "evidence_refs": []string{"pr:nhi-posture-1"}}); status != http.StatusOK {
		t.Fatalf("activate NHI posture policy = %d %s", status, raw)
	}
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")
	return h, reader, dormant, wide
}

func readNHIPostureAutomationPlan(t *testing.T, h *servedHarness, reader string) nhiPostureAutomationPlan {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/automation", reader, nil)
	var plan nhiPostureAutomationPlan
	if status != http.StatusOK || json.Unmarshal(body, &plan) != nil {
		t.Fatalf("automation plan = %d %s", status, body)
	}
	return plan
}

func automaticPlaybookRuns(t *testing.T, h *servedHarness) map[string]store.RemediationPlaybookRun {
	t.Helper()
	runs := map[string]store.RemediationPlaybookRun{}
	for _, playbook := range []string{"identity-revoke", "nhi-right-size"} {
		rows, err := h.store.ListRemediationPlaybookRunsPage(t.Context(), h.tenant, playbook, store.ZeroUUID, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.CreatedBy == "system:nhi-posture" {
				runs[row.PlaybookID+"/"+row.Status+"/"+row.InventoryID] = row
			}
		}
	}
	return runs
}

// A100: the tenant's nhi_posture rules drive automatic actions. The plan
// shows what each rule asks for; the leader's sweep revokes the dormant
// managed key through the lifecycle gate (with an RFC 5280 reason the
// publisher accepts) and queues the right-size intent for the unused grants,
// each as a playbook run naming the rule and the module; a rule asking for an
// unknown remediation is reported only; a second sweep changes nothing.
func TestServedNHIPostureRulesActAutomatically(t *testing.T) {
	h, reader, dormant, wide := nhiPostureAutomationFixture(t)
	plan := readNHIPostureAutomationPlan(t, h, reader)
	if plan.PolicyModuleSHA256 == "" || plan.PolicyEvaluated < 2 || plan.Summary.Revoke != 1 || plan.Summary.RightSize != 1 || plan.Summary.ReportOnly != 1 {
		t.Fatalf("plan = %+v; want one revoke, one right_size, one report_only", plan)
	}
	actions := map[string]string{}
	for _, item := range plan.Items {
		actions[item.InventoryID+"/"+item.Rule] = item.Action
		if item.LastRun != nil {
			t.Fatalf("a run exists before any sweep: %+v", item)
		}
	}
	if actions["identity/"+dormant+"/dormant-managed-revoke"] != "revoke" || actions["identity/"+wide+"/unused-scopes-trim"] != "right_size" ||
		actions["identity/"+dormant+"/static-watch"] != "report_only" {
		t.Fatalf("plan actions = %v", actions)
	}

	result, err := h.srv.runNHIPostureAutomationOnce(t.Context(), time.Now().UTC())
	if err != nil || result.Revoked != 1 || result.RightSized != 1 || result.Refused != 0 {
		t.Fatalf("sweep = %+v err=%v", result, err)
	}
	if got, err := h.store.GetIdentity(t.Context(), h.tenant, dormant); err != nil || got.Status != "revoked" {
		t.Fatalf("dormant key status = %s err=%v; want revoked", got.Status, err)
	}
	if got, err := h.store.GetIdentity(t.Context(), h.tenant, wide); err != nil || got.Status != "deployed" {
		t.Fatalf("right-sized account status = %s err=%v; right_size must not revoke", got.Status, err)
	}
	var payload []byte
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination='revocation.publish'`,
		h.tenant).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var intent struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &intent); err != nil || intent.Reason != "cessationOfOperation" {
		t.Fatalf("revocation intent reason = %q err=%v", intent.Reason, err)
	}
	var rightSizeIntents int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='connector.right_size'`,
		h.tenant).Scan(&rightSizeIntents); err != nil || rightSizeIntents != 1 {
		t.Fatalf("right-size intents = %d err=%v", rightSizeIntents, err)
	}
	runs := automaticPlaybookRuns(t, h)
	revoked, ok := runs["identity-revoke/executed/identity/"+dormant]
	if !ok || !strings.HasPrefix(revoked.Reason, "posture:dormant-managed-revoke") ||
		!containsString(revoked.EvidenceRefs, "nhi_posture_rule:dormant-managed-revoke") ||
		!containsString(revoked.EvidenceRefs, "policy:module:"+plan.PolicyModuleSHA256) {
		t.Fatalf("automatic revoke run = %+v (runs %v)", revoked, runs)
	}
	if queued, ok := runs["nhi-right-size/queued/identity/"+wide]; !ok || !containsString(queued.EvidenceRefs, "nhi_posture_rule:unused-scopes-trim") {
		t.Fatalf("automatic right-size run = %+v (runs %v)", queued, runs)
	}

	again, err := h.srv.runNHIPostureAutomationOnce(t.Context(), time.Now().UTC())
	if err != nil || again.Revoked != 0 || again.RightSized != 0 || again.Refused != 0 {
		t.Fatalf("second sweep = %+v err=%v; want no new action", again, err)
	}
	if after := automaticPlaybookRuns(t, h); len(after) != len(runs) {
		t.Fatalf("second sweep recorded runs: %v", after)
	}
	plan = readNHIPostureAutomationPlan(t, h, reader)
	for _, item := range plan.Items {
		if item.InventoryID == "identity/"+wide && item.Rule == "unused-scopes-trim" &&
			(item.LastRun == nil || item.LastRun.PlaybookID != "nhi-right-size" || item.LastRun.Status != "queued") {
			t.Fatalf("plan does not show the automatic right-size run: %+v", item)
		}
	}
}

// Under dual control an automatic revoke carries no exact approval: the gate
// refuses it, the refusal is a playbook run, the identity stays as it was,
// and the next sweep does not re-ask within the back-off.
func TestServedNHIPostureRevokeIsRefusedUnderDualControl(t *testing.T) {
	h, reader, dormant, _ := nhiPostureAutomationFixture(t, func(d *Deps) { d.RequireApproval = true })
	result, err := h.srv.runNHIPostureAutomationOnce(t.Context(), time.Now().UTC())
	if err != nil || result.Revoked != 0 || result.Refused != 1 {
		t.Fatalf("sweep = %+v err=%v; want the revoke refused", result, err)
	}
	if got, err := h.store.GetIdentity(t.Context(), h.tenant, dormant); err != nil || got.Status != "deployed" {
		t.Fatalf("refused revoke changed the identity: %s err=%v", got.Status, err)
	}
	refused, ok := automaticPlaybookRuns(t, h)["identity-revoke/refused/identity/"+dormant]
	if !ok || !strings.Contains(refused.Reason, "dual control") {
		t.Fatalf("refusal run = %+v", refused)
	}
	again, err := h.srv.runNHIPostureAutomationOnce(t.Context(), time.Now().UTC())
	if err != nil || again.Refused != 0 || again.Skipped < 1 {
		t.Fatalf("second sweep = %+v err=%v; want the refusal backed off", again, err)
	}
	plan := readNHIPostureAutomationPlan(t, h, reader)
	for _, item := range plan.Items {
		if item.InventoryID == "identity/"+dormant && item.Rule == "dormant-managed-revoke" && (item.LastRun == nil || item.LastRun.Status != "refused") {
			t.Fatalf("plan does not show the refusal: %+v", item)
		}
	}
}
