// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/oauthrevoke/oauthrevoketest"
)

// A171-L1: an application trstctl blocked at the provider can be unblocked
// there from the same finding: the Okta app is reactivated and the Entra
// service principal re-enabled by the outbox worker, each read back, and the
// finding records the unblock as confirmed beside the earlier block. Google,
// whose API cannot block an app, is refused here too. Before, reactivating the
// app or re-enabling the service principal was manual, in the provider's
// console.
func TestServedOAuthAppIsUnblockedAtTheProviderA171L1(t *testing.T) {
	const adminToken = "a171l1-provider-admin-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := oauthrevoketest.New(adminToken)
	t.Cleanup(stand.Close)
	stand.SeedOkta("00u-ivy", "0oa-unblock", 1, 0, "0oa-unblock")
	stand.SeedGraph("sp-unblock", oauthrevoketest.GraphGrant{ID: "g-jo", ClientID: "sp-unblock", PrincipalID: "user-jo"})
	stand.SeedGoogle("kim@example.com", "client-unblock.apps.googleusercontent.com")
	t.Setenv("TRSTCTL_A171L1_ADMIN_TOKEN", adminToken)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A171L1_ADMIN_TOKEN"))
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "connectors:write", string(authz.PrivateEgress))
	cidr := serviceNowSinkCIDR(t, stand.URL())
	connection := func(provider string) map[string]any {
		return map[string]any{"provider": provider, "base_url": stand.URL(), "token_ref": "env:TRSTCTL_A171L1_ADMIN_TOKEN", // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{cidr}}
	}
	grant := func(provider, app, user string) map[string]any {
		return map[string]any{"provider": provider, "app_id": app, "principal": user, "resource": provider + "-api",
			"scopes": []string{"offline_access"}, "threat_signals": []string{"consent_phishing"}, "evidence_refs": []string{"alert:" + app}}
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{"name": "a171l1-grants", "kind": "oauth_grant",
		"config": map[string]any{
			"grants": []any{grant("okta", "0oa-unblock", "00u-ivy"), grant("microsoft", "sp-unblock", "user-jo"),
				grant("google", "client-unblock.apps.googleusercontent.com", "kim@example.com")},
			"providers": []any{connection("okta"), connection("entra"), connection("google")},
		}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("create source: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
	var run struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatalf("run: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain run: %v", err)
	}
	findings := func() map[string]oauthFindingRow {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=oauth_grant_abuse&limit=100&run_id="+run.ID, tok, nil)
		var list struct {
			Items []oauthFindingRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		out := map[string]oauthFindingRow{}
		for _, f := range list.Items {
			out[f.Metadata["provider"].(string)] = f
		}
		return out
	}
	byProvider := findings()
	act := func(provider, action, key string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+byProvider[provider].ID+"/oauth-grant/"+action, tok, key,
			map[string]any{"reason": "a171-l1"})
	}
	for _, provider := range []string{"okta", "microsoft"} {
		if status, body := act(provider, "block", "a171l1-block-"+provider); status != http.StatusAccepted {
			t.Fatalf("block %s = %d %s", provider, status, body)
		}
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain blocks: %v", err)
	}
	if stand.OktaAppActive("0oa-unblock") || stand.GraphSPEnabled("sp-unblock") {
		t.Fatal("the blocks did not land")
	}
	for _, provider := range []string{"okta", "microsoft"} {
		status, body := act(provider, "unblock", "a171l1-unblock-"+provider)
		var queued struct {
			Action string `json:"action"`
			Status string `json:"status"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.Action != "unblock_app" || queued.Status != "queued" {
			t.Fatalf("unblock %s = %d %s", provider, status, body)
		}
	}
	if stand.GraphSPEnabled("sp-unblock") || stand.OktaAppActive("0oa-unblock") {
		t.Fatal("the request handler contacted the provider; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain unblocks: %v", err)
	}
	if !stand.OktaAppActive("0oa-unblock") || !stand.GraphSPEnabled("sp-unblock") {
		t.Fatal("the unblocks did not reactivate the app or re-enable the service principal")
	}
	after := findings()
	for _, provider := range []string{"okta", "microsoft"} {
		actions, _ := after[provider].Metadata["provider_actions"].(map[string]any)
		block, _ := actions["block_app"].(map[string]any)
		unblock, _ := actions["unblock_app"].(map[string]any)
		if block["status"] != "confirmed" || unblock["status"] != "confirmed" || !strings.Contains(unblock["detail"].(string), "read back:") {
			t.Fatalf("%s recorded actions = %+v", provider, actions)
		}
	}
	if status, body := act("google", "unblock", "a171l1-unblock-google"); status != http.StatusConflict || !strings.Contains(string(body), "admin console") {
		t.Fatalf("google unblock = %d %s; want refused", status, body)
	}
}
