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
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
	"trstctl.com/trstctl/internal/events"
)

// TestServedNetworkAPIDeviceRotationA270: an Arista EOS switch, a FortiGate
// and a BIG-IP, each a stand-in of its HTTPS management API, are configured
// as providers with their certificates pinned and private egress allowed to
// their address only. A device account's rotation is single-phase and refused
// until acknowledged; acknowledged, the durable worker changes it through the
// administrator (EOS restating the account's privilege and role), the device
// saves it, the new password signs in through the device's own sign-in and
// the old one is refused. EOS's enable password rotates. A device that
// reports the change but keeps the old password is rolled back to the
// predecessor, which still signs in. Discovery lists each device's accounts
// with their level and never a hash, and no password, token or hash reaches
// an event.
func TestServedNetworkAPIDeviceRotationA270(t *testing.T) {
	ctx := context.Background()
	start := func(dialect netdevicetest.Dialect, credential, level string) *netdevicetest.APIDevice {
		t.Helper()
		d, err := netdevicetest.StartAPI(dialect, "netadmin", credential, level)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(d.Close)
		return d
	}
	eos := start(netdevicetest.EOS, "eos-admin-password-1", "15")
	eos.AddAccount("ops", "eos-ops-password-1", "7", "network-operator")
	eos.SetEnableSecret("eos-enable-secret-1")
	forti := start(netdevicetest.FortiOS, "fortigate-api-token-1", "super_admin")
	forti.AddAccount("ops", "forti-ops-password-1", "prof_admin", "")
	bigip := start(netdevicetest.BIGIP, "bigip-admin-password-1", "admin")
	bigip.AddAccount("ops", "bigip-ops-password-1", "operator", "")

	device := func(id, typ string, d *netdevicetest.APIDevice, credential string, roles map[string]string) config.DynamicSecretProviderConfig {
		c := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: id, Type: typ, Endpoint: d.URL(), AdminUser: "netadmin",
			TLSCARef: writeServedCredentialFile(t, id+"-ca", string(d.CAPEM())), AllowPrivate: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"},
			RoleBindings: roles, MaxTTL: "1h", AllowStaticRotation: true}
		for role := range roles {
			c.AllowedRoles = append(c.AllowedRoles, role)
		}
		if typ == "fortigate" {
			c.APIKeyRef = writeServedCredentialFile(t, id+"-token", credential)
		} else {
			c.PasswordRef = writeServedCredentialFile(t, id+"-admin", credential)
		}
		return c
	}
	configs := []config.DynamicSecretProviderConfig{
		device("leaf-eos", "eos", eos, "eos-admin-password-1", map[string]string{"eos/ops": "ops", "eos/enable": "enable"}),
		device("edge-fortigate", "fortigate", forti, "fortigate-api-token-1", map[string]string{"fortigate/ops": "ops"}),
		device("lb-bigip", "bigip", bigip, "bigip-admin-password-1", map[string]string{"bigip/ops": "ops"}),
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	for name, mutate := range map[string]func(*config.DynamicSecretProviderConfig){
		"administrator bound": func(c *config.DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"bigip/ops": "netadmin"}
		},
		"root bound":         func(c *config.DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"bigip/ops": "root"} },
		"enable on bigip":    func(c *config.DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"bigip/ops": "enable"} },
		"no certificate pin": func(c *config.DynamicSecretProviderConfig) { c.TLSCARef = "" },
		"plain HTTP": func(c *config.DynamicSecretProviderConfig) {
			c.Endpoint = strings.Replace(c.Endpoint, "https:", "http:", 1)
		},
	} {
		bad := configs[2]
		bad.RoleBindings = map[string]string{"bigip/ops": "ops"}
		mutate(&bad)
		if config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{bad}}, true) == nil {
			t.Fatalf("%s: a misconfigured device provider was accepted", name)
		}
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	tok := seedScopedTokenSubject(t, sh.store, sh.tenant, "a270-api-operator", "secrets:read", "secrets:write", "access:read", "access:targets.write")
	seed := func(key, username, password string) {
		t.Helper()
		value, _ := json.Marshal(map[string]string{"username": username, "password": password})
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", tok, "a270-api-seed-"+key,
			map[string]any{"name": key, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed %s: %d %s", key, status, body)
		}
	}
	seed("eos/ops", "ops", "eos-ops-password-1")
	seed("eos/enable", "enable", "eos-enable-secret-1")
	seed("fortigate/ops", "ops", "forti-ops-password-1")
	seed("bigip/ops", "ops", "bigip-ops-password-1")
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
	stored := func(key string) string {
		t.Helper()
		status, body := secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/store/"+key, tok, nil)
		var view struct {
			Value string `json:"value"`
		}
		var credential struct {
			Password string `json:"password"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || json.Unmarshal([]byte(view.Value), &credential) != nil {
			t.Fatalf("read %s: %d", key, status)
		}
		return credential.Password
	}

	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/rotations", tok, "a270-api-unacknowledged",
		map[string]any{"provider": "lb-bigip", "key": "bigip/ops", "old_ref": "ops"}); status != http.StatusBadRequest ||
		!strings.Contains(string(body), "rotates in a single phase") {
		t.Fatalf("an unacknowledged device rotation: %d %s", status, body)
	}
	published := map[string]string{}
	for _, tc := range []struct {
		provider, key, old string
		d                  *netdevicetest.APIDevice
		level, role        string
	}{
		{"leaf-eos", "eos/ops", "eos-ops-password-1", eos, "7", "network-operator"},
		{"edge-fortigate", "fortigate/ops", "forti-ops-password-1", forti, "prof_admin", ""},
		{"lb-bigip", "bigip/ops", "bigip-ops-password-1", bigip, "operator", ""},
	} {
		saves := tc.d.Saves()
		view := run("a270-api-"+tc.provider, map[string]any{"provider": tc.provider, "key": tc.key, "old_ref": "ops", "acknowledge_single_phase": true})
		if view.Phase != "completed" || view.RotationPhase != "single_phase" || view.VerifyMode != "authenticated" || !view.CredentialValid {
			t.Fatalf("%s rotation: %+v", tc.provider, view)
		}
		current := stored(tc.key)
		if !tc.d.SignsIn("ops", current) || tc.d.SignsIn("ops", tc.old) {
			t.Fatalf("%s: the account did not move to the published password alone", tc.provider)
		}
		if tc.d.Level("ops") != tc.level || tc.d.Role("ops") != tc.role || tc.d.Saves() <= saves {
			t.Fatalf("%s: level %q role %q, or the change was not saved", tc.provider, tc.d.Level("ops"), tc.d.Role("ops"))
		}
		published[tc.key] = current
	}
	if view := run("a270-api-eos-enable", map[string]any{"provider": "leaf-eos", "key": "eos/enable", "old_ref": "enable", "acknowledge_single_phase": true}); view.Phase != "completed" || view.VerifyMode != "authenticated" {
		t.Fatalf("EOS enable password rotation: %+v", view)
	}
	if enable := stored("eos/enable"); enable == "eos-enable-secret-1" || string(eos.EnableSecret()) != enable {
		t.Fatal("the switch's enable password is not the published one")
	}

	forti.DropNextChanges(1)
	if view := run("a270-api-forti-rollback", map[string]any{"provider": "edge-fortigate", "key": "fortigate/ops", "old_ref": "ops", "acknowledge_single_phase": true}); view.Phase != "rolled_back" {
		t.Fatalf("an unverified FortiGate change was not rolled back: %+v", view)
	}
	if restored := stored("fortigate/ops"); restored != published["fortigate/ops"] || !forti.SignsIn("ops", restored) {
		t.Fatal("the rollback did not leave the predecessor published and signing in")
	}

	discovered := map[string]string{}
	for _, provider := range []string{"leaf-eos", "edge-fortigate", "lb-bigip"} {
		if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/discovery/sources/"+provider, tok, "a270-api-source-"+provider,
			map[string]any{"interval_seconds": 3600}); status != http.StatusOK && status != http.StatusCreated {
			t.Fatalf("save the %s discovery source: %d %s", provider, status, body)
		}
		status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/discovery/sources/"+provider+"/runs", tok, "a270-api-scan-"+provider, nil)
		var queued a260Run
		if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil {
			t.Fatalf("scan %s: %d %s", provider, status, body)
		}
		if run := awaitQueuedDiscoveryProofA267(t, sh, tok, queued.ID); run.Status != "completed" {
			t.Fatalf("the %s scan: %+v", provider, run)
		}
		status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id="+provider, tok, nil)
		var page struct {
			Items []a260Account `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("list %s accounts: %d %s", provider, status, body)
		}
		for _, a := range page.Items {
			discovered[provider+"/"+a.Name] = strings.Join(a.Privileges, " ")
		}
	}
	for account, want := range map[string]string{"leaf-eos/ops": "privilege 7 role network-operator", "leaf-eos/netadmin": "privilege 15",
		"edge-fortigate/ops": "accprofile prof_admin", "edge-fortigate/netadmin": "accprofile super_admin",
		"lb-bigip/ops": "role operator on all-partitions", "lb-bigip/netadmin": "role admin on all-partitions"} {
		if discovered[account] != want {
			t.Fatalf("discovered %s = %q, want %q (all %v)", account, discovered[account], want, discovered)
		}
	}

	leaks := [][]byte{[]byte("eos-admin-password-1"), []byte("fortigate-api-token-1"), []byte("bigip-admin-password-1"), []byte("$6$"), []byte("ENC SH2")}
	for _, v := range published {
		leaks = append(leaks, []byte(v))
	}
	if err = sh.log.Replay(ctx, 0, func(event events.Event) error {
		for _, s := range leaks {
			if event.TenantID == sh.tenant && bytes.Contains(event.Data, s) {
				t.Fatalf("a device credential or hash reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
