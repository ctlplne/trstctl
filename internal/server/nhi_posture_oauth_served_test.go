// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/oauthrevoke/oauthrevoketest"
	"trstctl.com/trstctl/internal/policy"
)

const nhiPostureOAuthModule = policy.BaseModule + `
nhi_posture contains {"rule": "abusive-oauth-revoke", "severity": "critical", "reason": "abusive grants are revoked at the provider", "remediation": "revoke_oauth_grant"} if {
	input.action == "nhi_posture"
	"malicious_oauth_grant" in input.nhi.finding_types
	input.nhi.provider != "microsoft"
}

nhi_posture contains {"rule": "abusive-entra-app-block", "severity": "critical", "reason": "abusive Entra apps are blocked", "remediation": "block_oauth_app"} if {
	input.action == "nhi_posture"
	"oauth_abuse" in input.nhi.posture
	input.nhi.provider == "microsoft"
}

nhi_posture contains {"rule": "abusive-google-app-block", "severity": "high", "reason": "abusive Google apps are blocked", "remediation": "block_oauth_app"} if {
	input.action == "nhi_posture"
	"oauth_abuse" in input.nhi.posture
	input.nhi.provider == "google"
}
`

type nhiPostureOAuthPlanItem struct {
	InventoryID string `json:"inventory_id"`
	Rule        string `json:"rule"`
	Remediation string `json:"remediation"`
	Action      string `json:"action"`
	Detail      string `json:"detail"`
	LastRun     *struct {
		ID         string `json:"id"`
		PlaybookID string `json:"playbook_id"`
		Status     string `json:"status"`
		Phase      string `json:"phase"`
	} `json:"last_run"`
}

// A170-L3 Done-when: a policy-driven response acts at the provider when an
// abusive OAuth grant is detected, with no operator in the loop. The tenant's
// active module declares nhi_posture rules over the new oauth_abuse family:
// revoke abusive grants (but block abusive Entra applications), and block
// abusive Google applications, which Google's API cannot do. After discovery
// detects the grants, the plan shows each action — the Google block
// not_applicable with the operator's own reason — and the leader's sweep
// queues the same durable request and outbox row the operator's buttons
// queue: Okta and Google revoke exactly the detected user's grant, Entra
// disables the service principal, and each finding records the action with
// actor system:nhi-posture and the rule. A second sweep changes nothing. A
// provider that refuses the admin token records the failure; the sweep asks
// again only after the 24-hour back-off, as a new request.
func TestServedNHIPostureRuleActsAtTheProviderOnAnAbusiveOAuthGrantA170L3(t *testing.T) {
	const adminToken = "a170l3-provider-admin-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := oauthrevoketest.New(adminToken)
	t.Cleanup(stand.Close)
	stand.SeedOkta("00u-alice", "0oa-exfil", 2, 1, "0oa-exfil")
	stand.SeedOkta("00u-bob", "0oa-exfil", 1, 0, "")
	stand.SeedGraph("sp-exfil", oauthrevoketest.GraphGrant{ID: "g1", ClientID: "sp-exfil", PrincipalID: "user-carol"},
		oauthrevoketest.GraphGrant{ID: "g2", ClientID: "sp-exfil", PrincipalID: "user-dave"})
	stand.SeedGoogle("erin@example.com", "client-exfil.apps.googleusercontent.com")
	t.Setenv("TRSTCTL_A170L3_ADMIN_TOKEN", adminToken)
	t.Setenv("TRSTCTL_A170L3_WRONG_TOKEN", "not-the-admin-token")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.EnablePolicyGate = true },
		allowOutboundEnvCredentialRefs("env:TRSTCTL_A170L3_ADMIN_TOKEN", "env:TRSTCTL_A170L3_WRONG_TOKEN"))
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "connectors:write", "nhi:read", string(authz.PrivateEgress))
	author := seedScopedTokenSubject(t, h.store, h.tenant, "oauth-posture-author@example.test", "policy:read", "policy:write")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions", author, "a170l3-policy-create", map[string]any{
		"kind": "lifecycle", "description": "Act on abusive OAuth grants", "change_ref": "github:security/oauth-posture#1",
		"evidence_refs": []string{"pr:oauth-posture-1"}, "module": nhiPostureOAuthModule,
	})
	var created struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ID == "" {
		t.Fatalf("create policy = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions/"+created.ID+"/activate", author, "a170l3-policy-activate",
		map[string]any{"reason": "OAuth posture rules reviewed", "evidence_refs": []string{"pr:oauth-posture-1"}}); status != http.StatusOK {
		t.Fatalf("activate policy = %d %s", status, raw)
	}

	cidr := serviceNowSinkCIDR(t, stand.URL())
	connection := func(provider, ref string) map[string]any {
		return map[string]any{"provider": provider, "base_url": stand.URL(), "token_ref": ref,
			"allow_private_endpoint": true, "private_egress_cidrs": []string{cidr}}
	}
	grant := func(provider, app, user string) map[string]any {
		return map[string]any{"provider": provider, "app_id": app, "principal": user, "resource": provider + "-directory",
			"scopes": []string{"directory.read.all"}, "threat_signals": []string{"impossible_travel_consent"},
			"evidence_refs": []string{"provider-alert:" + app}, "source_event_ref": "export:" + app + ":" + user}
	}
	discover := func(name string, config map[string]any) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{"name": name, "kind": "oauth_grant", "config": config})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
			t.Fatalf("create %s: %d %s", name, status, body)
		}
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID}); status != http.StatusCreated {
			t.Fatalf("run %s: %d %s", name, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", name, err)
		}
		return source.ID
	}
	sourceID := discover("idp-grants", map[string]any{
		"grants": []any{grant("okta", "0oa-exfil", "00u-alice"), grant("microsoft", "sp-exfil", "user-carol"),
			grant("google", "client-exfil.apps.googleusercontent.com", "erin@example.com")},
		"providers": []any{connection("okta", "env:TRSTCTL_A170L3_ADMIN_TOKEN"), connection("entra", "env:TRSTCTL_A170L3_ADMIN_TOKEN"),
			connection("google", "env:TRSTCTL_A170L3_ADMIN_TOKEN")},
	})
	abuse := func(source string) map[string]oauthFindingRow {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=oauth_grant_abuse&limit=100", tok, nil)
		var list struct {
			Items []oauthFindingRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		out := map[string]oauthFindingRow{}
		for _, f := range list.Items {
			if f.SourceID == source {
				out[f.Metadata["provider"].(string)] = f
			}
		}
		return out
	}
	found := abuse(sourceID)
	if len(found) != 3 {
		t.Fatalf("abuse findings = %+v", found)
	}
	plan := func() (map[string]nhiPostureOAuthPlanItem, map[string]int) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/automation", tok, nil)
		var out struct {
			Summary map[string]int            `json:"summary"`
			Items   []nhiPostureOAuthPlanItem `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("automation plan = %d %s", status, body)
		}
		items := map[string]nhiPostureOAuthPlanItem{}
		for _, item := range out.Items {
			items[item.InventoryID+"/"+item.Rule] = item
		}
		return items, out.Summary
	}
	key := func(provider, rule string) string { return "finding/" + found[provider].ID + "/" + rule }
	items, summary := plan()
	if items[key("okta", "abusive-oauth-revoke")].Action != "revoke_oauth_grant" ||
		items[key("google", "abusive-oauth-revoke")].Action != "revoke_oauth_grant" ||
		items[key("microsoft", "abusive-entra-app-block")].Action != "block_oauth_app" {
		t.Fatalf("plan items = %+v", items)
	}
	if google := items[key("google", "abusive-google-app-block")]; google.Action != "not_applicable" || !strings.Contains(google.Detail, "admin console") {
		t.Fatalf("google block = %+v; want not_applicable naming the admin console", google)
	}
	if summary["revoke_oauth_grant"] != 2 || summary["block_oauth_app"] != 1 {
		t.Fatalf("plan summary = %v", summary)
	}
	for _, item := range items {
		if item.LastRun != nil {
			t.Fatalf("an action exists before any sweep: %+v", item)
		}
	}

	providerRows := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='oauth.provider_action'`,
			h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	result, err := h.srv.runNHIPostureAutomationOnce(ctx, time.Now().UTC())
	if err != nil || result.Revoked != 0 || result.RightSized != 0 || result.Refused != 0 {
		t.Fatalf("sweep = %+v err=%v", result, err)
	}
	if n := providerRows(); n != 3 {
		t.Fatalf("provider action rows = %d; want the Okta and Google revokes and the Entra block", n)
	}
	if grants, tokens := stand.OktaGrants("00u-alice", "0oa-exfil"); grants != 2 || tokens != 1 {
		t.Fatal("the sweep contacted the provider; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the automatic actions: %v", err)
	}
	if grants, tokens := stand.OktaGrants("00u-alice", "0oa-exfil"); grants != 0 || tokens != 0 {
		t.Fatalf("okta kept alice's grants %d tokens %d", grants, tokens)
	}
	if grants, _ := stand.OktaGrants("00u-bob", "0oa-exfil"); grants != 1 {
		t.Fatal("the automatic revoke touched another user's grant")
	}
	if stand.GraphSPEnabled("sp-exfil") || stand.GoogleToken("erin@example.com", "client-exfil.apps.googleusercontent.com") {
		t.Fatal("the Entra block or the Google revoke did not land")
	}
	if !stand.OktaAppActive("0oa-exfil") || stand.GraphGrants("sp-exfil", "user-dave") != 1 {
		t.Fatal("an automatic action reached past what its rule asked for")
	}
	for provider, action := range map[string]string{"okta": "revoke_grant", "microsoft": "block_app", "google": "revoke_grant"} {
		actions, _ := abuse(sourceID)[provider].Metadata["provider_actions"].(map[string]any)
		if state, _ := actions[action].(map[string]any); state["status"] != "confirmed" {
			t.Fatalf("%s %s state = %+v", provider, action, state)
		}
	}
	var actor, reason string
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		var data struct {
			FindingID string `json:"finding_id"`
			Status    string `json:"status"`
			Actor     string `json:"actor"`
			Reason    string `json:"reason"`
		}
		if e.TenantID == h.tenant && e.Type == "discovery.finding.provider_action" && json.Unmarshal(e.Data, &data) == nil &&
			data.FindingID == found["okta"].ID && data.Status == "queued" {
			actor, reason = data.Actor, data.Reason
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if actor != "system:nhi-posture" || !strings.HasPrefix(reason, "posture:abusive-oauth-revoke") ||
		!strings.Contains(reason, "nhi_posture_rule:abusive-oauth-revoke") || !strings.Contains(reason, "policy:module:") {
		t.Fatalf("queued action actor %q reason %q", actor, reason)
	}
	items, _ = plan()
	if run := items[key("okta", "abusive-oauth-revoke")].LastRun; run == nil || run.Status != "confirmed" || run.Phase != "revoke_grant" {
		t.Fatalf("plan does not show the confirmed revoke: %+v", items[key("okta", "abusive-oauth-revoke")])
	}
	again, err := h.srv.runNHIPostureAutomationOnce(ctx, time.Now().UTC())
	if err != nil || again.Skipped < 3 {
		t.Fatalf("second sweep = %+v err=%v; want the settled actions left alone", again, err)
	}
	if n := providerRows(); n != 3 {
		t.Fatalf("second sweep queued again: %d rows", n)
	}
	if stand.Unauthorized() != 0 {
		t.Fatalf("the stand-in refused %d requests", stand.Unauthorized())
	}

	// A provider that refuses the admin token: the failure is recorded, the
	// next sweep inside the back-off leaves it, and a sweep after it asks
	// again as a new request.
	wrongID := discover("idp-grants-wrong-token", map[string]any{
		"grants":    []any{grant("okta", "0oa-exfil", "00u-bob")},
		"providers": []any{connection("okta", "env:TRSTCTL_A170L3_WRONG_TOKEN")},
	})
	wrong := abuse(wrongID)["okta"]
	if _, err := h.srv.runNHIPostureAutomationOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the refused revoke: %v", err)
	}
	failed := func() map[string]any {
		t.Helper()
		actions, _ := abuse(wrongID)["okta"].Metadata["provider_actions"].(map[string]any)
		state, _ := actions["revoke_grant"].(map[string]any)
		return state
	}
	first := failed()
	if first["status"] != "failed" || !strings.Contains(first["detail"].(string), "status 401") {
		t.Fatalf("refused automatic revoke = %+v", first)
	}
	if n := providerRows(); n != 4 {
		t.Fatalf("provider action rows = %d; want one for the refused revoke", n)
	}
	if _, err := h.srv.runNHIPostureAutomationOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if n := providerRows(); n != 4 {
		t.Fatalf("the sweep asked again inside the back-off: %d rows", n)
	}
	if _, err := h.srv.runNHIPostureAutomationOnce(ctx, time.Now().UTC().Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := providerRows(); n != 5 {
		t.Fatalf("the sweep after the back-off did not ask again: %d rows", n)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the retried revoke: %v", err)
	}
	if retried := failed(); retried["status"] != "failed" || retried["request_id"] == first["request_id"] {
		t.Fatalf("retried revoke = %+v (first %+v); want a new request", retried, first)
	}
	if grants, _ := stand.OktaGrants("00u-bob", "0oa-exfil"); grants != 1 || wrong.ID == "" {
		t.Fatal("a refused token removed a grant")
	}
}
