// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/credref"
	"trstctl.com/trstctl/internal/store"
)

func TestCR064ConnectorCredentialStopsWhenItsConfigurerLosesSecretRead(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "cr064-connector-admin", "access:write", "secrets:read", "secrets:write")
	leaver := seedScopedTokenSubject(t, h.store, h.tenant, "cr064-connector-leaver", "secrets:read", "secrets:write", "connectors:read", "connectors:write")
	stayer := seedScopedTokenSubject(t, h.store, h.tenant, "cr064-connector-stayer", "secrets:read", "secrets:write", "connectors:read", "connectors:write")
	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "cr064-connector-project", map[string]any{
		"slug": "vault64connector", "environments": []any{map[string]any{"slug": "prod", "restricted": true}},
	}, http.StatusCreated)
	for _, subject := range []string{"cr064-connector-leaver", "cr064-connector-stayer"} {
		call(admin, http.MethodPut, "/api/v1/secrets/projects/vault64connector/members/"+subject,
			"cr064-connector-member-"+subject, map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	}
	call(leaver, http.MethodPost, "/api/v1/secrets/store", "cr064-connector-secret", map[string]any{
		"name": "vault64connector/prod/token", "value": "connector-canary-v1",
	}, http.StatusCreated)
	targetConfig := map[string]any{"endpoint": "https://kemp.example.test", "token_ref": "secret://vault64connector/prod/token"}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(leaver, http.MethodPost, "/api/v1/connectors/targets", "cr064-connector-target", map[string]any{
		"name": "cr064-kemp", "connector": "kemp", "config": targetConfig,
	}, http.StatusCreated), &created); err != nil || created.ID == "" {
		t.Fatalf("decode saved connector target: %v", err)
	}
	client, err := connectorHTTPClientFromConfig(config.Connectors{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := nativeConnectorRuntime{cfg: config.Connectors{}, store: h.store, kek: h.kek,
		crypto: h.srv.tenantCrypto, httpClient: client}
	build := func(target store.DeploymentTarget) error {
		t.Helper()
		_, _, cleanup, err := buildHTTPConnector(runtime, t.Context(), "kemp", connector.DeployPayload{
			TenantID: h.tenant, TargetID: target.ID, TargetRevision: target.RevisionID, TargetConfig: target.Config,
		})
		if cleanup != nil {
			cleanup()
		}
		return err
	}
	old, err := h.store.GetDeploymentTarget(t.Context(), h.tenant, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := build(old); err != nil {
		t.Fatalf("authorized connector could not open its saved credential: %v", err)
	}
	relay := relayCredentialResolver{store: h.store, kek: h.kek, tenantCrypto: h.srv.tenantCrypto}
	redeem := func(target store.DeploymentTarget) error {
		t.Helper()
		material, err := relay.resolveTargetReferenceNames(t.Context(), h.tenant, target.ID, target.RevisionID,
			target.Type, target.Config, []string{"secret://vault64connector/prod/token"})
		if err == nil {
			material.wipe()
		}
		return err
	}
	if err := redeem(old); err != nil {
		t.Fatalf("authorized relay could not redeem the saved target revision: %v", err)
	}
	changed := old
	changed.Config = json.RawMessage(`{"endpoint":"https://attacker.example.test","token_ref":"secret://vault64connector/prod/token"}`)
	if err := build(changed); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("connector accepted a different endpoint under the saved revision: %v", err)
	}
	call(admin, http.MethodDelete, "/api/v1/secrets/projects/vault64connector/members/cr064-connector-leaver",
		"cr064-connector-remove", nil, http.StatusOK)
	call(stayer, http.MethodPut, "/api/v1/secrets/store/vault64connector/prod/token", "cr064-connector-rotate",
		map[string]any{"value": "connector-canary-v2"}, http.StatusOK)
	if err := build(old); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("connector opened rotated secret after its configurer lost read: %v", err)
	}
	if err := redeem(old); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("relay redeemed rotated secret after its configurer lost read: %v", err)
	}
	call(stayer, http.MethodPut, "/api/v1/connectors/targets/"+created.ID, "cr064-connector-reauthorize", map[string]any{
		"name": "cr064-kemp", "connector": "kemp", "config": targetConfig,
	}, http.StatusOK)
	current, err := h.store.GetDeploymentTarget(t.Context(), h.tenant, created.ID)
	if err != nil || current.RevisionID == old.RevisionID {
		t.Fatalf("reauthorized connector has no new revision: %v", err)
	}
	if err := build(current); err != nil {
		t.Fatalf("currently authorized connector could not open the secret: %v", err)
	}
	if err := redeem(current); err != nil {
		t.Fatalf("currently authorized relay could not redeem the secret: %v", err)
	}
	if err := build(old); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("old target revision borrowed the new configurer's authority: %v", err)
	}
}
