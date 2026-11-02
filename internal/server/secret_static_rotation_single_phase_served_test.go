// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// servedAuth0 is a stand-in for an Auth0 tenant built from Auth0's API
// documentation: the client-credentials grant at /oauth/token and the
// Management API's POST /api/v2/clients/{id}/rotate-secret, which replaces the
// application's secret at once.
type servedAuth0 struct {
	mu      sync.Mutex
	secrets map[string]string
	serial  int
}

func (f *servedAuth0) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
		var grant map[string]string
		_ = json.NewDecoder(r.Body).Decode(&grant)
		if current, ok := f.secrets[grant["client_id"]]; !ok || current != grant["client_secret"] || grant["grant_type"] != "client_credentials" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		if grant["client_id"] != "mgmtClient001" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"access_denied"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"served-mgmt-token","token_type":"Bearer"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/clients/appClient0001/rotate-secret":
		if r.Header.Get("Authorization") != "Bearer served-mgmt-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.serial++
		f.secrets["appClient0001"] = "rotated-secret-" + strings.Repeat("r", f.serial)
		_ = json.NewEncoder(w).Encode(map[string]string{"client_id": "appClient0001", "client_secret": f.secrets["appClient0001"]})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *servedAuth0) authenticates(t *testing.T, url, clientSecret string) bool {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"grant_type": "client_credentials", "client_id": "appClient0001",
		"client_secret": clientSecret, "audience": url + "/api/v2/"})
	resp, err := http.Post(url+"/oauth/token", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusForbidden // authenticated, not authorized for the Management API
}

// A240: a single-phase provider warns before it runs. Auth0 invalidates an
// application's client secret the moment it issues the next one, so the
// preview says so and blocks until the request acknowledges it, and an
// unacknowledged rotation or schedule is refused. An acknowledged rotation
// runs through the durable worker: the new secret authenticates, the old one
// stops at once, and the command records the phase and the acknowledgement.
func TestServedSinglePhaseRotationWarnsBeforeItRunsA240(t *testing.T) {
	tenant := &servedAuth0{secrets: map[string]string{"mgmtClient001": "served-mgmt-secret", "appClient0001": "original-app-secret"}}
	stand := httptest.NewServer(tenant)
	defer stand.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "auth0-tenant", Type: "auth0", Endpoint: stand.URL, ClientID: "mgmtClient001",
		ClientSecretRef: writeServedCredentialFile(t, "auth0-mgmt", "served-mgmt-secret"),
		AllowedRoles:    []string{"auth0/orders"}, RoleBindings: map[string]string{"auth0/orders": "appClient0001"},
		MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A240 single-phase tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := context.Background()
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-auth0",
		map[string]any{"name": "auth0/orders", "value": `{"client_id":"appClient0001","client_secret":"original-app-secret"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	rotation := map[string]any{"provider": "auth0-tenant", "key": "auth0/orders", "old_ref": "none"}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations/preview", tok, rotation)
	if status != http.StatusOK || !strings.Contains(string(body), `"ready":false`) || !strings.Contains(string(body), "set acknowledge_single_phase to run it") ||
		!strings.Contains(string(body), "invalidates the current one at once") {
		t.Fatalf("unacknowledged single-phase preview: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, rotation)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "rotates in a single phase") {
		t.Fatalf("unacknowledged single-phase rotation: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
		map[string]any{"name": "auth0-daily", "provider": "auth0-tenant", "key": "auth0/orders", "old_ref": "none", "interval_seconds": 86400})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "rotates in a single phase") {
		t.Fatalf("unacknowledged single-phase schedule: %d %s", status, body)
	}
	if !tenant.authenticates(t, stand.URL, "original-app-secret") {
		t.Fatal("a refused rotation touched the application's secret")
	}

	rotation["acknowledge_single_phase"] = true
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations/preview", tok, rotation)
	if status != http.StatusOK || !strings.Contains(string(body), `"ready":true`) {
		t.Fatalf("acknowledged single-phase preview: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "auth0-rotate-1", rotation)
	var queued struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
		t.Fatalf("acknowledged single-phase rotation: %d %s", status, body)
	}
	var view staticRotationCommandView
	for deadline := time.Now().Add(30 * time.Second); ; {
		h.srv.dispatchOnce(ctx)
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
			t.Fatalf("read the command: %d %s", status, body)
		}
		if view.Terminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the single-phase rotation did not finish: %s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if view.Phase != "completed" || view.RotationPhase != "single_phase" || !view.SinglePhaseAcknowledged ||
		view.VerifyMode != "authenticated" || !view.CredentialValid || view.ResultVersion != 2 {
		t.Fatalf("the acknowledged single-phase command: %+v", view)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/auth0/orders", tok, nil)
	var stored struct {
		Value string `json:"value"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &stored) != nil {
		t.Fatalf("read the rotated secret: %d", status)
	}
	var credential struct {
		ClientSecret string `json:"client_secret"`
	}
	if json.Unmarshal([]byte(stored.Value), &credential) != nil || !tenant.authenticates(t, stand.URL, credential.ClientSecret) {
		t.Fatal("the published secret does not authenticate the application")
	}
	if tenant.authenticates(t, stand.URL, "original-app-secret") {
		t.Fatal("the previous secret still authenticates after a single-phase rotation")
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "auth0-schedule",
		map[string]any{"name": "auth0-daily", "provider": "auth0-tenant", "key": "auth0/orders", "old_ref": "none",
			"interval_seconds": 86400, "acknowledge_single_phase": true})
	if (status != http.StatusCreated && status != http.StatusOK) || !strings.Contains(string(body), `"single_phase_acknowledged":true`) {
		t.Fatalf("acknowledged single-phase schedule: %d %s", status, body)
	}
}
