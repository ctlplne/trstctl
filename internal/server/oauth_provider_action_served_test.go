// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/oauthrevoke/oauthrevoketest"
)

type oauthFindingRow struct {
	ID       string         `json:"id"`
	SourceID string         `json:"source_id"`
	Kind     string         `json:"kind"`
	Metadata map[string]any `json:"metadata"`
}

// A170/A171 Done-when: live action at the provider on an abusive OAuth grant.
// An oauth_grant source found abusive grants at Okta, Microsoft Entra and
// Google Workspace and names an admin connection for each by token reference.
// Revoking a finding's grant removes exactly that user's grant to that
// application at the provider; blocking deactivates the Okta app and disables
// the Entra service principal so no one can grant them again; Google, whose
// API cannot block an app, is refused with the reason. Each finding records
// the request and then what the provider confirmed. A token the provider
// refuses records the failure with its status rather than retrying forever.
func TestServedOAuthGrantRevokedAndAppBlockedAtTheProvider(t *testing.T) {
	const adminToken = "a170-provider-admin-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := oauthrevoketest.New(adminToken)
	t.Cleanup(stand.Close)
	stand.SeedOkta("00u-alice", "0oa-exfil", 2, 1, "0oa-exfil")
	stand.SeedOkta("00u-bob", "0oa-exfil", 1, 0, "")
	stand.SeedGraph("sp-exfil", oauthrevoketest.GraphGrant{ID: "g1", ClientID: "sp-exfil", PrincipalID: "user-carol"},
		oauthrevoketest.GraphGrant{ID: "g2", ClientID: "sp-exfil", PrincipalID: "user-dave"})
	stand.SeedGoogle("erin@example.com", "client-exfil.apps.googleusercontent.com")
	t.Setenv("TRSTCTL_A170_ADMIN_TOKEN", adminToken)
	t.Setenv("TRSTCTL_A170_WRONG_TOKEN", "not-the-admin-token")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A170_ADMIN_TOKEN", "env:TRSTCTL_A170_WRONG_TOKEN"))
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "connectors:write", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
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
	createSource := func(name string, config map[string]any) string {
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
	sourceID := createSource("idp-grants", map[string]any{
		"grants": []any{grant("okta", "0oa-exfil", "00u-alice"), grant("microsoft", "sp-exfil", "user-carol"),
			grant("google", "client-exfil.apps.googleusercontent.com", "erin@example.com")},
		"providers": []any{connection("okta", "env:TRSTCTL_A170_ADMIN_TOKEN"), connection("entra", "env:TRSTCTL_A170_ADMIN_TOKEN"),
			connection("google", "env:TRSTCTL_A170_ADMIN_TOKEN")},
	})
	findings := func(source string) map[string]oauthFindingRow {
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
			if f.Kind == "oauth_grant_abuse" && f.SourceID == source {
				out[f.Metadata["provider"].(string)] = f
			}
		}
		return out
	}
	abuse := findings(sourceID)
	if len(abuse) != 3 {
		t.Fatalf("abuse findings = %+v", abuse)
	}
	act := func(findingID, action, key string, token string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+findingID+"/oauth-grant/"+action, token, key, map[string]any{"reason": "a170 confirmed abuse"})
	}
	actionState := func(findingID, action string) map[string]any {
		t.Helper()
		for _, f := range findings(sourceID) {
			if f.ID == findingID {
				actions, _ := f.Metadata["provider_actions"].(map[string]any)
				state, _ := actions[action].(map[string]any)
				return state
			}
		}
		return nil
	}

	if status, body := act(abuse["okta"].ID, "revoke", "a170-reader", reader); status != http.StatusForbidden {
		t.Fatalf("revoke without connectors:write = %d %s", status, body)
	}
	status, body := act(abuse["okta"].ID, "revoke", "a170-okta-revoke", tok)
	var queued struct {
		RequestID string `json:"request_id"`
		Action    string `json:"action"`
		Provider  string `json:"provider"`
		AppID     string `json:"app_id"`
		Principal string `json:"principal"`
		Status    string `json:"status"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.Status != "queued" || queued.Provider != "okta" ||
		queued.AppID != "0oa-exfil" || queued.Principal != "00u-alice" {
		t.Fatalf("okta revoke = %d %s", status, body)
	}
	if status, replay := act(abuse["okta"].ID, "revoke", "a170-okta-revoke", tok); status != http.StatusAccepted || !bytes.Equal(replay, body) {
		t.Fatalf("replay = %d %s", status, replay)
	}
	if state := actionState(abuse["okta"].ID, "revoke_grant"); state["status"] != "queued" {
		t.Fatalf("finding before delivery = %+v", state)
	}
	if grants, tokens := stand.OktaGrants("00u-alice", "0oa-exfil"); grants != 2 || tokens != 1 {
		t.Fatal("the request handler contacted the provider; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain okta revoke: %v", err)
	}
	if grants, tokens := stand.OktaGrants("00u-alice", "0oa-exfil"); grants != 0 || tokens != 0 {
		t.Fatalf("okta kept alice's grants %d tokens %d", grants, tokens)
	}
	if grants, _ := stand.OktaGrants("00u-bob", "0oa-exfil"); grants != 1 {
		t.Fatal("the revoke touched another user's grant")
	}
	if state := actionState(abuse["okta"].ID, "revoke_grant"); state["status"] != "confirmed" || !strings.Contains(state["detail"].(string), "Okta revoked") {
		t.Fatalf("finding after okta revoke = %+v", state)
	}

	for _, step := range []struct{ provider, action, key string }{
		{"okta", "block", "a170-okta-block"}, {"microsoft", "revoke", "a170-graph-revoke"},
		{"microsoft", "block", "a170-graph-block"}, {"google", "revoke", "a170-google-revoke"},
	} {
		if status, body := act(abuse[step.provider].ID, step.action, step.key, tok); status != http.StatusAccepted {
			t.Fatalf("%s %s = %d %s", step.provider, step.action, status, body)
		}
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the remaining actions: %v", err)
	}
	if stand.OktaAppActive("0oa-exfil") || stand.GraphSPEnabled("sp-exfil") || stand.GraphGrants("sp-exfil", "user-carol") != 0 ||
		stand.GraphGrants("sp-exfil", "user-dave") != 1 || stand.GoogleToken("erin@example.com", "client-exfil.apps.googleusercontent.com") {
		t.Fatal("a provider action did not land, or reached past its grant")
	}
	for provider, action := range map[string]string{"okta": "block_app", "microsoft": "revoke_grant", "google": "revoke_grant"} {
		if state := actionState(abuse[provider].ID, action); state["status"] != "confirmed" {
			t.Fatalf("%s %s state = %+v", provider, action, state)
		}
	}
	if status, body := act(abuse["google"].ID, "block", "a170-google-block", tok); status != http.StatusConflict || !bytes.Contains(body, []byte("admin console")) {
		t.Fatalf("google block = %d %s; want 409 naming the console", status, body)
	}
	if stand.Unauthorized() != 0 {
		t.Fatalf("the stand-in refused %d requests", stand.Unauthorized())
	}

	// A token the provider refuses records the failure with its status.
	wrongID := createSource("idp-grants-wrong-token", map[string]any{
		"grants":    []any{grant("okta", "0oa-exfil", "00u-bob")},
		"providers": []any{connection("okta", "env:TRSTCTL_A170_WRONG_TOKEN")},
	})
	wrong := findings(wrongID)["okta"]
	if status, body := act(wrong.ID, "revoke", "a170-wrong-revoke", tok); status != http.StatusAccepted {
		t.Fatalf("revoke on the wrong-token source = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the refused revoke: %v", err)
	}
	for _, f := range findings(wrongID) {
		actions, _ := f.Metadata["provider_actions"].(map[string]any)
		state, _ := actions["revoke_grant"].(map[string]any)
		if f.ID == wrong.ID && (state["status"] != "failed" || !strings.Contains(state["detail"].(string), "status 401")) {
			t.Fatalf("refused revoke state = %+v", state)
		}
	}
	if grants, _ := stand.OktaGrants("00u-bob", "0oa-exfil"); grants != 1 {
		t.Fatal("a refused token revoked a grant")
	}

	// A source with no admin connection for the grant's provider is refused.
	bareID := createSource("idp-grants-no-connection", map[string]any{"grants": []any{grant("okta", "0oa-other", "00u-frank")}})
	if status, body := act(findings(bareID)["okta"].ID, "revoke", "a170-bare-revoke", tok); status != http.StatusConflict || !bytes.Contains(body, []byte("no admin connection")) {
		t.Fatalf("revoke without a connection = %d %s", status, body)
	}
}
