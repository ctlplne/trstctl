// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/mdm"
)

// A156: an Intune poll schedule names an Entra app registration instead of a
// hand-rotated bearer. The schedule stores and serves only its identifiers,
// refuses unsafe or mismatched registrations, and the dispatched relay job
// carries them so the relay exchanges the redeemed client secret per attempt
// (the exchange itself is proven in internal/agent/relay).
func TestServedIntuneScheduleCarriesTheAppRegistrationToTheRelay(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	seedMDMTestRelay(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	const directory, clientID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	base := map[string]any{
		"mdm": "intune", "base_url": "https://graph.microsoft.com", "token_ref": servedMDMSecretRef,
		"interval_seconds": 3600, "enabled": true, "execution": "relay", "required_agent_id": agentRowID(h.tenant, "relay-1"),
	}
	with := func(changes map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range changes {
			out[k] = v
		}
		return out
	}
	for name, body := range map[string]map[string]any{
		"jamf with an Entra app": with(map[string]any{"mdm": "jamf", "base_url": "https://jamf.internal.example",
			"client_credentials": map[string]any{"directory_tenant_id": directory, "client_id": clientID}}),
		"client id not a GUID": with(map[string]any{"client_credentials": map[string]any{"directory_tenant_id": directory, "client_id": "my-app"}}),
		"plain http authority": with(map[string]any{"client_credentials": map[string]any{"authority": "http://login.example.test",
			"directory_tenant_id": directory, "client_id": clientID}}),
		"tenant path injection": with(map[string]any{"client_credentials": map[string]any{"directory_tenant_id": "../common", "client_id": clientID}}),
	} {
		if status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok, "a156-bad-"+name, body); status != http.StatusBadRequest {
			t.Errorf("%s: status %d %s; want 400", name, status, out)
		}
	}

	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok, "a156-intune",
		with(map[string]any{"client_credentials": map[string]any{"directory_tenant_id": directory, "client_id": clientID}}))
	if status != http.StatusOK {
		t.Fatalf("configure Intune schedule with an app registration: %d %s", status, out)
	}
	var saved struct {
		TokenRef          string                 `json:"token_ref"`
		ClientCredentials *mdm.ClientCredentials `json:"client_credentials"`
		Guidance          string                 `json:"guidance"`
	}
	if err := json.Unmarshal(out, &saved); err != nil || saved.ClientCredentials == nil ||
		saved.ClientCredentials.ClientID != clientID || saved.ClientCredentials.DirectoryTenantID != directory ||
		saved.ClientCredentials.Authority != mdm.DefaultEntraAuthority || saved.TokenRef != servedMDMSecretRef ||
		!strings.Contains(saved.Guidance, "client_credentials") {
		t.Fatalf("schedule response = %s; want the app registration identifiers, the default authority and the secret reference", out)
	}
	status, listed := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/poll-schedule", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(listed), clientID) {
		t.Fatalf("schedule list = %d %s; want the app registration served", status, listed)
	}

	sched, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || !found {
		t.Fatalf("load schedule: found=%v err=%v", found, err)
	}
	h.srv.dispatchMDMSyncJob(t.Context(), h.tenant, sched)
	var payload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'mdm.sync'`, h.tenant).Scan(&payload)
	}); err != nil {
		t.Fatalf("load the dispatched mdm.sync job: %v", err)
	}
	var intent mdm.SyncIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatalf("decode intent: %v", err)
	}
	if intent.ClientCredentials == nil || intent.ClientCredentials.ClientID != clientID ||
		intent.ClientCredentials.DirectoryTenantID != directory || intent.TokenRef != servedMDMSecretRef {
		t.Fatalf("relay intent = %+v; want the app registration and the client secret reference", intent)
	}
	if _, err := intent.ClientCredentials.TokenEndpoint(); err != nil {
		t.Fatalf("the dispatched app registration does not name a token endpoint: %v", err)
	}
}
