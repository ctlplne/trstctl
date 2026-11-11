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

// A170-L1: a Microsoft Entra application an administrator consented to for
// every user (Graph consentType AllPrincipals, no principal) is revoked as
// the tenant's grant: the request is accepted, the outbox worker deletes
// exactly that admin consent at Graph, each user's own grant to the
// application stays, and the finding records what Graph confirmed. A grant
// that names no user and is not the tenant's admin consent is still refused.
// Before, every grant without a user was refused with "block the application
// instead", so an admin consent could only be left in place or the whole
// application disabled.
func TestServedTenantWideAdminConsentIsRevokedA170L1(t *testing.T) {
	const adminToken = "a170l1-provider-admin-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := oauthrevoketest.New(adminToken)
	t.Cleanup(stand.Close)
	stand.SeedGraph("sp-consented",
		oauthrevoketest.GraphGrant{ID: "g-all", ClientID: "sp-consented", ConsentType: "AllPrincipals"},
		oauthrevoketest.GraphGrant{ID: "g-frank", ClientID: "sp-consented", PrincipalID: "user-frank"})
	stand.SeedGraph("sp-orphan")
	t.Setenv("TRSTCTL_A170L1_ADMIN_TOKEN", adminToken)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A170L1_ADMIN_TOKEN"))
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "connectors:write", string(authz.PrivateEgress))
	grant := func(app, consent string) map[string]any {
		return map[string]any{"provider": "microsoft", "app_id": app, "resource": "graph", "consent_type": consent,
			"scopes": []string{"Mail.ReadWrite"}, "threat_signals": []string{"admin_consent_to_unverified_publisher"},
			"evidence_refs": []string{"provider-alert:" + app}, "source_event_ref": "export:" + app}
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{"name": "entra-consents", "kind": "oauth_grant",
		"config": map[string]any{
			"grants": []any{grant("sp-consented", "AllPrincipals"), grant("sp-orphan", "Principal")},
			"providers": []any{map[string]any{"provider": "entra", "base_url": stand.URL(), "token_ref": "env:TRSTCTL_A170L1_ADMIN_TOKEN", // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
				"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())}}},
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
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.ID == "" {
		t.Fatalf("run: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain run: %v", err)
	}
	byApp := func() map[string]oauthFindingRow {
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
			if f.SourceID == source.ID {
				out[f.Metadata["app_id"].(string)] = f
			}
		}
		return out
	}
	found := byApp()
	consented, orphan := found["sp-consented"], found["sp-orphan"]
	if consented.ID == "" || orphan.ID == "" {
		t.Fatalf("abuse findings = %+v", found)
	}
	revoke := func(findingID, key string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+findingID+"/oauth-grant/revoke", tok, key,
			map[string]any{"reason": "a170-l1 consent to an unverified publisher"})
	}
	status, body = revoke(consented.ID, "a170l1-tenant-revoke")
	var queued struct {
		Status    string `json:"status"`
		AppID     string `json:"app_id"`
		Principal string `json:"principal"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.Status != "queued" || queued.AppID != "sp-consented" ||
		queued.Principal != "" {
		t.Fatalf("tenant-wide revoke = %d %s", status, body)
	}
	if stand.GraphTenantWideGrants("sp-consented") != 1 {
		t.Fatal("the request handler contacted Graph; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain revoke: %v", err)
	}
	if stand.GraphTenantWideGrants("sp-consented") != 0 || stand.GraphGrants("sp-consented", "user-frank") != 1 {
		t.Fatalf("after the revoke: admin consents %d, frank's grants %d; want the admin consent gone and frank's kept",
			stand.GraphTenantWideGrants("sp-consented"), stand.GraphGrants("sp-consented", "user-frank"))
	}
	actions, _ := byApp()["sp-consented"].Metadata["provider_actions"].(map[string]any)
	state, _ := actions["revoke_grant"].(map[string]any)
	if state["status"] != "confirmed" || !strings.Contains(state["detail"].(string), "admin consent for all users") {
		t.Fatalf("recorded action = %+v", state)
	}
	if status, body := revoke(orphan.ID, "a170l1-orphan-revoke"); status != http.StatusConflict || !strings.Contains(string(body), "names no user") {
		t.Fatalf("a grant with no user that is not the admin consent = %d %s; want refused", status, body)
	}
}
