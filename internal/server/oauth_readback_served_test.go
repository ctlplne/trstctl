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

// A170-L2: after the provider confirms a revoke, trstctl reads the grant back
// before recording it. A grant that is gone is recorded confirmed with the
// read back in its detail; a provider that acknowledges the removal but still
// lists the grant (one that re-grants on its own) is recorded failed, naming
// what is left, instead of confirmed. Before, the provider's acknowledgement
// alone was recorded as confirmed and only the next discovery run re-checked.
func TestServedOAuthRevokeReadsTheGrantBackA170L2(t *testing.T) {
	const adminToken = "a170l2-provider-admin-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	honest, sticky := oauthrevoketest.New(adminToken), oauthrevoketest.New(adminToken)
	t.Cleanup(honest.Close)
	t.Cleanup(sticky.Close)
	honest.SeedGraph("sp-honest", oauthrevoketest.GraphGrant{ID: "g-h", ClientID: "sp-honest", PrincipalID: "user-gina"})
	sticky.SeedGraph("sp-sticky", oauthrevoketest.GraphGrant{ID: "g-s", ClientID: "sp-sticky", PrincipalID: "user-hank"})
	sticky.SetSticky(true)
	t.Setenv("TRSTCTL_A170L2_ADMIN_TOKEN", adminToken)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A170L2_ADMIN_TOKEN"))
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "connectors:write", string(authz.PrivateEgress))
	finding := func(name string, stand *oauthrevoketest.Server, app, user string) oauthFindingRow {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{"name": name, "kind": "oauth_grant",
			"config": map[string]any{
				"grants": []any{map[string]any{"provider": "microsoft", "app_id": app, "principal": user, "resource": "graph",
					"scopes": []string{"Mail.Read"}, "threat_signals": []string{"impossible_travel_consent"}, "evidence_refs": []string{"alert:" + app}}},
				"providers": []any{map[string]any{"provider": "entra", "base_url": stand.URL(), "token_ref": "env:TRSTCTL_A170L2_ADMIN_TOKEN", // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
					"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())}}},
			}})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
			t.Fatalf("create %s: %d %s", name, status, body)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
		var run struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
			t.Fatalf("run %s: %d %s", name, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", name, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=oauth_grant_abuse&limit=100&run_id="+run.ID, tok, nil)
		var list struct {
			Items []oauthFindingRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 1 {
			t.Fatalf("findings of %s: %d %s", name, status, body)
		}
		return list.Items[0]
	}
	state := func(findingID string) map[string]any {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?id="+findingID, tok, nil)
		var list struct {
			Items []oauthFindingRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 1 {
			t.Fatalf("finding %s: %d %s", findingID, status, body)
		}
		actions, _ := list.Items[0].Metadata["provider_actions"].(map[string]any)
		out, _ := actions["revoke_grant"].(map[string]any)
		return out
	}
	gina := finding("a170l2-honest", honest, "sp-honest", "user-gina")
	hank := finding("a170l2-sticky", sticky, "sp-sticky", "user-hank")
	for key, f := range map[string]oauthFindingRow{"a170l2-revoke-gina": gina, "a170l2-revoke-hank": hank} {
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+f.ID+"/oauth-grant/revoke", tok, key,
			map[string]any{"reason": "a170-l2 read back"}); status != http.StatusAccepted {
			t.Fatalf("revoke %s = %d %s", key, status, body)
		}
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain revokes: %v", err)
	}
	if got := state(gina.ID); got["status"] != "confirmed" || !strings.Contains(got["detail"].(string), "read back: Microsoft Graph lists no delegated grant") ||
		honest.GraphGrants("sp-honest", "user-gina") != 0 {
		t.Fatalf("the honest provider's revoke = %+v", got)
	}
	if got := state(hank.ID); got["status"] != "failed" || !strings.Contains(got["detail"].(string), "still lists a delegated grant") {
		t.Fatalf("the provider that kept the grant = %+v; want failed, naming what is left", got)
	}
}
