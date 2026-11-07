// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/events"
)

// TestServedIdPAdminRotationA272: Okta, Entra ID and Google Workspace
// stand-ins are configured as providers of their break-glass super
// administrators. Each rotation is single-phase and refused until
// acknowledged; acknowledged, the worker sets the password through the
// identity provider's administration API. Okta and Entra prove it with one
// sign-in (an MFA step after the right password counts, and Okta's pending
// transaction is cancelled), Google reports not available. The old password
// stops; a change the provider keeps out is rolled back; the accounts never
// reach their lockout threshold; no password reaches an event.
func TestServedIdPAdminRotationA272(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.NewString()
	okta := infratest.StartOkta("okta-api-token-1")
	t.Cleanup(okta.Close)
	entra := infratest.StartEntra("app-client-1", "app-secret-1")
	t.Cleanup(entra.Close)
	google, err := infratest.StartGoogle("rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(google.Close)
	for _, p := range []*infratest.IdP{okta, entra, google} {
		p.AddUser("breakglass@corp.example", "initial-password-1!", true)
	}
	base := func(id, typ, role string) config.DynamicSecretProviderConfig {
		return config.DynamicSecretProviderConfig{TenantID: tenant, ID: id, Type: typ, AllowInsecureLoopback: true, MaxTTL: "1h", AllowStaticRotation: true,
			AllowedRoles: []string{role}, RoleBindings: map[string]string{role: "breakglass@corp.example"}}
	}
	oktaCfg := base("okta-org", "okta-user", "idp/okta-breakglass")
	oktaCfg.Endpoint, oktaCfg.APIKeyRef = okta.URL(), writeServedCredentialFile(t, "a272-okta-token", "okta-api-token-1")
	entraCfg := base("entra-tenant", "entra-user", "idp/entra-breakglass")
	entraCfg.Endpoint, entraCfg.AuthorityHost, entraCfg.AzureTenant, entraCfg.ClientID = entra.URL(), entra.URL(), "corp-tenant", "app-client-1"
	entraCfg.ClientSecretRef = writeServedCredentialFile(t, "a272-entra-secret", "app-secret-1")
	googleCfg := base("workspace", "google-workspace-user", "idp/google-breakglass")
	googleCfg.Endpoint, googleCfg.AuthorityHost = google.URL(), google.URL()+"/token"
	googleCfg.ServiceAccount, googleCfg.AdminUser = "rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example"
	googleCfg.PrivateKeyRef = writeServedCredentialFile(t, "a272-google-key", string(google.ServiceAccountKeyPEM()))
	configs := []config.DynamicSecretProviderConfig{oktaCfg, entraCfg, googleCfg}
	if err = config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	for name, mutate := range map[string]func(*config.DynamicSecretProviderConfig){
		"impersonated admin bound": func(c *config.DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"idp/google-breakglass": "admin@corp.example"}
		},
		"no service account key": func(c *config.DynamicSecretProviderConfig) { c.PrivateKeyRef = "" },
		"leases":                 func(c *config.DynamicSecretProviderConfig) { c.AllowStaticRotation = false },
	} {
		bad := googleCfg
		bad.RoleBindings = map[string]string{"idp/google-breakglass": "breakglass@corp.example"}
		mutate(&bad)
		if config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{bad}}, true) == nil {
			t.Fatalf("%s: a misconfigured identity provider was accepted", name)
		}
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: registry.ForTenant(tenant)}
	})
	registerServedTenantID(t, h, tenant, "A272 identity provider administrators")
	tok := seedScopedToken(t, h.store, tenant, "secrets:read", "secrets:write")
	run := func(key string, request map[string]any) staticRotationCommandView {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, key, request)
		var queued struct {
			CommandID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		var view staticRotationCommandView
		for deadline := time.Now().Add(90 * time.Second); ; {
			staticRotationDueFor(t, h, tenant)
			h.srv.dispatchOnce(ctx)
			status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("read %s: %d %s", key, status, body)
			}
			if view.Terminal {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not finish: %s", key, body)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	stored := func(name string) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+name, tok, nil)
		var view struct {
			Value string `json:"value"`
		}
		var credential struct {
			Password string `json:"password"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || json.Unmarshal([]byte(view.Value), &credential) != nil {
			t.Fatalf("read %s: %d", name, status)
		}
		return credential.Password
	}
	var leaks [][]byte
	for _, tc := range []struct {
		provider, key string
		idp           *infratest.IdP
		mode          string
	}{
		{"okta-org", "idp/okta-breakglass", okta, "authenticated"},
		{"entra-tenant", "idp/entra-breakglass", entra, "authenticated"},
		{"workspace", "idp/google-breakglass", google, "not_available"},
	} {
		value, _ := json.Marshal(map[string]string{"username": "breakglass@corp.example", "password": "initial-password-1!"})
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "a272-seed-"+tc.provider, map[string]any{"name": tc.key, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed %s: %d %s", tc.key, status, body)
		}
		request := map[string]any{"provider": tc.provider, "key": tc.key, "old_ref": "breakglass@corp.example"}
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "a272-unack-"+tc.provider, request); status != http.StatusBadRequest ||
			!strings.Contains(string(body), "rotates in a single phase") {
			t.Fatalf("%s: an unacknowledged rotation: %d %s", tc.provider, status, body)
		}
		request["acknowledge_single_phase"] = true
		view := run("a272-rotate-"+tc.provider, request)
		if view.Phase != "completed" || view.RotationPhase != "single_phase" || view.VerifyMode != tc.mode {
			t.Fatalf("%s rotation: %+v", tc.provider, view)
		}
		current := stored(tc.key)
		if string(tc.idp.Password("breakglass@corp.example")) != current || current == "initial-password-1!" {
			t.Fatalf("%s: the identity provider does not hold the published password", tc.provider)
		}
		if tc.mode == "authenticated" {
			tc.idp.DropNextChanges(1)
			if view := run("a272-rotate-dropped-"+tc.provider, request); view.Phase != "rolled_back" {
				t.Fatalf("%s: an unproven change was not rolled back: %+v", tc.provider, view)
			}
			if restored := stored(tc.key); restored != current || string(tc.idp.Password("breakglass@corp.example")) != current {
				t.Fatalf("%s: the rollback did not keep the predecessor", tc.provider)
			}
		}
		if tc.idp.Locked("breakglass@corp.example") || tc.idp.Failed("breakglass@corp.example") >= infratest.LockoutThreshold || tc.idp.Pending() != 0 {
			t.Fatalf("%s: failed=%d locked=%v pending=%d", tc.provider, tc.idp.Failed("breakglass@corp.example"), tc.idp.Locked("breakglass@corp.example"), tc.idp.Pending())
		}
		leaks = append(leaks, []byte(current))
	}
	leaks = append(leaks, []byte("okta-api-token-1"), []byte("app-secret-1"), []byte("initial-password-1!"))
	if err = h.log.Replay(ctx, 0, func(event events.Event) error {
		for _, s := range leaks {
			if event.TenantID == tenant && bytes.Contains(event.Data, s) {
				t.Fatalf("an administrator credential reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
