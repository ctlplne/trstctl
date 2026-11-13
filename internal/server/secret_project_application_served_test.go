// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A235-L5 Done-when: a project's application view joins by the owner's CMDB
// application. The project's owner (Payments team) and another team
// (Platform team) both name application APP-PAY; the view of the project
// names the application, spans both owners, and counts the Platform team's
// identity; a project owned by a team with no application shows its own
// holdings only.
func TestServedSecretProjectApplicationViewSpansTheCMDBApplicationA235L5(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "secrets-admin", "access:write", "secrets:read", "secrets:write")
	owner := func(name, application string) store.Owner {
		t.Helper()
		o, err := h.srv.orch.CreateOwnerRecord(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: name, ApplicationID: application})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	payments, platform, solo := owner("Payments team", "APP-PAY"), owner("Platform team", "APP-PAY"), owner("Solo team", "")
	if err := h.store.UpsertIdentity(t.Context(), store.Identity{ID: "11111111-1111-1111-1111-1111111a2351", TenantID: h.tenant,
		Kind: store.KindAPIKey, Name: "platform-gateway-key", OwnerID: platform.ID, Status: "deployed", Attributes: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	type view struct {
		Owner          string `json:"owner"`
		OwnerResources *struct {
			ApplicationID string `json:"application_id"`
			Owners        int    `json:"owners"`
			Identities    int    `json:"identities"`
		} `json:"owner_resources"`
	}
	project := func(slug, ownerID string) view {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects", admin, "a235l5-"+slug, map[string]any{
			"slug": slug, "owner_id": ownerID, "environments": []map[string]any{{"slug": "prod"}}}); status != http.StatusCreated {
			t.Fatalf("create %s = %d %s", slug, status, body)
		}
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/projects/"+slug, admin, nil)
		var v view
		if status != http.StatusOK || json.Unmarshal(body, &v) != nil || v.OwnerResources == nil {
			t.Fatalf("show %s = %d %s", slug, status, body)
		}
		return v
	}
	if v := project("payments-app", payments.ID); v.Owner != "Payments team" || v.OwnerResources.ApplicationID != "APP-PAY" ||
		v.OwnerResources.Owners != 2 || v.OwnerResources.Identities != 1 {
		t.Fatalf("payments application view = %+v; want APP-PAY across both owners with the Platform team's identity", v.OwnerResources)
	}
	if v := project("solo-app", solo.ID); v.OwnerResources.ApplicationID != "" || v.OwnerResources.Owners != 1 || v.OwnerResources.Identities != 0 {
		t.Fatalf("solo view = %+v", v.OwnerResources)
	}
}
