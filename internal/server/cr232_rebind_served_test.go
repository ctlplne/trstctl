// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// CR-232: an ordinary provider reconfiguration must not strand the issued
// lease. The outbox must delete the old vendor key, then report completion.
func TestCR232ServedRebindRevokesTheIssuedOpenAIKey(t *testing.T) {
	organization := &servedOpenAIOrganization{accounts: map[string][3]string{}}
	stand := httptest.NewServer(organization)
	defer stand.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "openai-org", Type: "openai", Endpoint: stand.URL,
		APIKeyRef:    writeServedCredentialFile(t, "cr232-openai-admin", "served-openai-admin-key"),
		AllowedRoles: []string{"openai/orders"}, RoleBindings: map[string]string{"openai/orders": "proj_orders"},
		UsernamePrefix: "trstctl", MaxTTL: "1h", AllowInsecureLoopback: true,
	}}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, serverTestPrincipalKEK(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "CR-232 OpenAI tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, "cr232-issue",
		map[string]any{"provider": "openai-org", "role": "openai/orders", "ttl_seconds": 600})
	var lease dynamicLeaseView
	if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &lease) != nil || lease.Credential == "" {
		t.Fatalf("issue: %d %s", status, body)
	}
	var credential struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.APIKey == "" ||
		!organization.authenticates(t, stand.URL, credential.APIKey) {
		t.Fatalf("issued key does not authenticate: %v", err)
	}
	issued, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, lease.ID)
	if err != nil || !strings.HasPrefix(issued.BackendRef, "v3:") {
		t.Fatalf("issued reference lacks bound owner and key: %v", err)
	}
	// The provider object is reopened for the outbox call. Simulate the new
	// validated configuration after the issuance has completed.
	current := registry[h.tenant][0].(*configuredDynamicProvider)
	current.cfg.RoleBindings = map[string]string{"openai/orders": "proj_billing"}
	current.cfg.UsernamePrefix = "new-prefix"
	if status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", token, "cr232-revoke", map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("queue revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, token, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("provider revocation did not complete after rebind: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if organization.authenticates(t, stand.URL, credential.APIKey) {
		t.Fatal("revocation claimed complete while the vendor key still authenticates")
	}
}

func TestCR232ServedRebindRevokesTheIssuedHostedKey(t *testing.T) {
	vendor := &servedOpenRouter{keys: map[string][2]string{}, limits: map[string]any{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "openrouter-account", Type: "openrouter", Endpoint: stand.URL + "/api/v1",
		APIKeyRef:    writeServedCredentialFile(t, "cr232-openrouter-admin", "served-openrouter-management-key"),
		AllowedRoles: []string{"inference"}, RoleBindings: map[string]string{"inference": "limit 25"},
		UsernamePrefix: "trstctl", MaxTTL: "1h", AllowInsecureLoopback: true,
	}}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, serverTestPrincipalKEK(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "CR-232 OpenRouter tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, "cr232-hosted-issue",
		map[string]any{"provider": "openrouter-account", "role": "inference", "ttl_seconds": 600})
	var lease dynamicLeaseView
	if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &lease) != nil || lease.Credential == "" {
		t.Fatalf("issue: %d %s", status, body)
	}
	var credential struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.APIKey == "" {
		t.Fatalf("issued key is missing: %v", err)
	}
	authenticates := func() bool {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, stand.URL+"/api/v1/key", nil)
		req.Header.Set("Authorization", "Bearer "+credential.APIKey)
		response, err := stand.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode == http.StatusOK
	}
	if !authenticates() {
		t.Fatal("issued hosted key does not authenticate")
	}
	current := registry[h.tenant][0].(*configuredDynamicProvider)
	current.cfg.RoleBindings = map[string]string{"inference": "unlimited"}
	current.cfg.UsernamePrefix = "later"
	if status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", token, "cr232-hosted-revoke", map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("queue hosted revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(8 * time.Second); ; {
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, token, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hosted revocation did not complete after rebind: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if authenticates() {
		t.Fatal("hosted revocation claimed complete while the vendor key still authenticates")
	}
}

func TestCR232ServedRotationRetiresTheIssuedPredecessorAfterRebind(t *testing.T) {
	vendor := &servedOpenRouter{keys: map[string][2]string{}, limits: map[string]any{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "openrouter-account", Type: "openrouter", Endpoint: stand.URL + "/api/v1",
		APIKeyRef:    writeServedCredentialFile(t, "cr232-rotation-admin", "served-openrouter-management-key"),
		AllowedRoles: []string{"inference"}, RoleBindings: map[string]string{"inference": "limit 25"},
		UsernamePrefix: "trstctl", MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
	}}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, serverTestPrincipalKEK(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "CR-232 rotation tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "cr232-seed",
		map[string]any{"name": "inference", "value": `{"api_key":"outside-fixture"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, body)
	}
	rotate := func(key, oldRef string) string {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, key,
			map[string]any{"provider": "openrouter-account", "key": "inference", "old_ref": oldRef, "retire_after_seconds": 1})
		var queued struct {
			CommandID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
			t.Fatalf("queue rotation: %d %s", status, body)
		}
		return queued.CommandID
	}
	await := func(id string) staticRotationCommandView {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); ; {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, token, nil)
			var view staticRotationCommandView
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("read rotation: %d %s", status, body)
			}
			if view.Terminal {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("rotation did not finish: %+v", view)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	first := await(rotate("cr232-rotation-first", "none"))
	if first.Phase != store.SecretStaticRotationCompleted || !strings.HasPrefix(first.NewRef, "v3:") {
		t.Fatalf("first rotation did not issue a bound key: %+v", first)
	}
	vendor.mu.Lock()
	if len(vendor.keys) != 1 {
		vendor.mu.Unlock()
		t.Fatalf("first rotation left %d keys", len(vendor.keys))
	}
	var predecessor string
	for _, key := range vendor.keys {
		predecessor = key[1]
	}
	vendor.mu.Unlock()
	current := registry[h.tenant][0].(*configuredDynamicProvider)
	current.cfg.RoleBindings = map[string]string{"inference": "unlimited"}
	current.cfg.UsernamePrefix = "later"
	second := await(rotate("cr232-rotation-second", first.NewRef))
	if second.Phase != store.SecretStaticRotationCompleted || second.OldRef != first.NewRef {
		t.Fatalf("predecessor retirement after rebind failed: %+v", second)
	}
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	if len(vendor.keys) != 1 {
		t.Fatalf("rotation left %d keys; want the one successor", len(vendor.keys))
	}
	for _, key := range vendor.keys {
		if key[1] == predecessor {
			t.Fatal("original binding's predecessor key stayed live")
		}
	}
}
