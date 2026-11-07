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

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/events"
)

// TestServedESXiRotationA271: an ESXi host's vSphere Web Services API (a
// stand-in) is configured as a provider with its certificate pinned and
// egress limited to its address. A rotation of a local account is
// single-phase and refused until acknowledged; acknowledged, the durable
// worker changes the password with UpdateUser in an administrator session and
// proves it by signing in as the account, and the old password is refused. A
// host that keeps the old password is rolled back to the predecessor.
// vpxuser cannot be bound. Discovery lists each local user with its role;
// every session is logged out; no password reaches an event.
func TestServedESXiRotationA271(t *testing.T) {
	ctx := context.Background()
	bmc := infratest.StartESXi("root", "bmc-admin-password-1")
	t.Cleanup(bmc.Close)
	bmc.AddAccount("ops", "bmc-ops-password-1", -1)
	bmc.AddAccount("monitor", "bmc-monitor-password-1", -2)
	bmc.AddAccount("vpxuser", "managed-by-vcenter", -1)
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "rack-bmc", Type: "esxi", Endpoint: bmc.URL(),
		TLSCARef: writeServedCredentialFile(t, "a271-esxi-ca", string(bmc.CAPEM())), AllowPrivate: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"},
		AdminUser: "root", PasswordRef: writeServedCredentialFile(t, "a271-esxi-admin", "bmc-admin-password-1"),
		AllowedRoles: []string{"bmc/ops"}, RoleBindings: map[string]string{"bmc/ops": "ops"}, MaxTTL: "1h", AllowStaticRotation: true}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	for name, mutate := range map[string]func(*config.DynamicSecretProviderConfig){
		"administrator bound": func(c *config.DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"bmc/ops": "root"}
		},
		"no certificate pin": func(c *config.DynamicSecretProviderConfig) { c.TLSCARef = "" },
		"vpxuser bound":      func(c *config.DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"bmc/ops": "vpxuser"} },
		"an SSH route":       func(c *config.DynamicSecretProviderConfig) { c.Addr = "127.0.0.1:22" },
		"leases":             func(c *config.DynamicSecretProviderConfig) { c.AllowStaticRotation = false },
	} {
		bad := cfg
		bad.RoleBindings = map[string]string{"bmc/ops": "ops"}
		mutate(&bad)
		if config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{bad}}, true) == nil {
			t.Fatalf("%s: a misconfigured host provider was accepted", name)
		}
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	tok := seedScopedTokenSubject(t, sh.store, sh.tenant, "a271-esxi-operator", "secrets:read", "secrets:write", "access:read", "access:targets.write")
	value, _ := json.Marshal(map[string]string{"username": "ops", "password": "bmc-ops-password-1"})
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", tok, "a271-esxi-seed", map[string]any{"name": "bmc/ops", "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, body)
	}
	run := func(idempotency string, request map[string]any) staticRotationCommandView {
		t.Helper()
		status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotency, request)
		var queued struct {
			CommandID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
			t.Fatalf("queue %s: %d %s", idempotency, status, body)
		}
		var view staticRotationCommandView
		for deadline := time.Now().Add(90 * time.Second); ; {
			a270StaticRotationDue(t, sh)
			sh.srv.dispatchOnce(ctx)
			status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("read %s: %d %s", idempotency, status, body)
			}
			if view.Terminal {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not finish: %s", idempotency, body)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	stored := func() string {
		t.Helper()
		status, body := secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/store/bmc/ops", tok, nil)
		var view struct {
			Value string `json:"value"`
		}
		var credential struct {
			Password string `json:"password"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || json.Unmarshal([]byte(view.Value), &credential) != nil {
			t.Fatalf("read the vault: %d", status)
		}
		return credential.Password
	}
	request := map[string]any{"provider": "rack-bmc", "key": "bmc/ops", "old_ref": "ops"}
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/rotations", tok, "a271-esxi-unacknowledged", request); status != http.StatusBadRequest ||
		!strings.Contains(string(body), "rotates in a single phase") {
		t.Fatalf("an unacknowledged host rotation: %d %s", status, body)
	}
	request["acknowledge_single_phase"] = true
	view := run("a271-esxi-rotate-1", request)
	if view.Phase != "completed" || view.RotationPhase != "single_phase" || view.VerifyMode != "authenticated" || !view.CredentialValid {
		t.Fatalf("the host rotation: %+v", view)
	}
	current := stored()
	if !bmc.SignsIn("ops", current) || bmc.SignsIn("ops", "bmc-ops-password-1") {
		t.Fatal("the account did not move to the published password alone")
	}
	bmc.DropNextChanges(1)
	if view := run("a271-esxi-rotate-2", request); view.Phase != "rolled_back" {
		t.Fatalf("an unproven host change was not rolled back: %+v", view)
	}
	if restored := stored(); restored != current || !bmc.SignsIn("ops", restored) {
		t.Fatal("the rollback did not leave the predecessor published and opening sessions")
	}

	if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/discovery/sources/rack-bmc", tok, "a271-esxi-source",
		map[string]any{"interval_seconds": 3600}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("save the discovery source: %d %s", status, body)
	}
	status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/discovery/sources/rack-bmc/runs", tok, "a271-esxi-scan", nil)
	var queued a260Run
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("scan: %d %s", status, body)
	}
	if run := awaitQueuedDiscoveryProofA267(t, sh, tok, queued.ID); run.Status != "completed" {
		t.Fatalf("the scan: %+v", run)
	}
	status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=rack-bmc", tok, nil)
	var page struct {
		Items []a260Account `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("list accounts: %d %s", status, body)
	}
	found := map[string]string{}
	for _, a := range page.Items {
		found[a.Name] = strings.Join(a.Privileges, " ")
	}
	if found["ops"] != "role Admin" || found["monitor"] != "role ReadOnly" || found["root"] != "role Admin" || found["vpxuser"] != "role Admin" {
		t.Fatalf("discovered %v", found)
	}
	if bmc.Sessions() != 0 {
		t.Fatalf("%d host sessions were left open", bmc.Sessions())
	}
	leaks := [][]byte{[]byte("bmc-admin-password-1"), []byte("bmc-ops-password-1"), []byte(current)}
	if err = sh.log.Replay(ctx, 0, func(event events.Event) error {
		for _, s := range leaks {
			if event.TenantID == sh.tenant && bytes.Contains(event.Data, s) {
				t.Fatalf("a host password reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
