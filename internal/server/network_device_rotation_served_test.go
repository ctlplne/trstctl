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

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

// TestServedNetworkDeviceRotationA270: an IOS-XE and a Junos device, each a
// stand-in that speaks its vendor's CLI over SSH, are configured as
// providers. A rotation of a device account is single-phase and refused until
// acknowledged; acknowledged, the durable worker changes the password on the
// device through the administrator, keeps the account's privilege level,
// saves the configuration and proves the new password signs in, and the old
// one is refused. IOS-XE's enable secret rotates and is proved by entering
// privileged mode. A device that reports the change but keeps the old
// password fails verification and is rolled back to the predecessor, which
// still signs in. Discovery lists each device's local accounts with their
// privilege or login class and never a hash, and no password or hash reaches
// an event.
func TestServedNetworkDeviceRotationA270(t *testing.T) {
	ctx := context.Background()
	iosxe, err := netdevicetest.Start(netdevicetest.IOSXE, "netadmin", "iosxe-admin-password-1", "privilege 15")
	if err != nil {
		t.Fatal(err)
	}
	defer iosxe.Close()
	iosxe.AddAccount("ops", "ops-password-1", "privilege 7")
	iosxe.SetEnableSecret("enable-secret-1")
	junos, err := netdevicetest.Start(netdevicetest.Junos, "netadmin", "junos-admin-password-1", "super-user")
	if err != nil {
		t.Fatal(err)
	}
	defer junos.Close()
	junos.AddAccount("noc", "noc-password-1", "operator")

	configs := []config.DynamicSecretProviderConfig{
		{TenantID: servedTestTenant, ID: "core-iosxe", Type: "iosxe", Addr: iosxe.Addr(), HostKeyFingerprint: iosxe.FingerprintSHA256(),
			AdminUser: "netadmin", PasswordRef: writeServedCredentialFile(t, "a270-iosxe-admin", "iosxe-admin-password-1"),
			AllowedRoles: []string{"net/ops", "net/enable"}, RoleBindings: map[string]string{"net/ops": "ops", "net/enable": "enable"},
			MaxTTL: "1h", AllowStaticRotation: true},
		{TenantID: servedTestTenant, ID: "edge-junos", Type: "junos", Addr: junos.Addr(), HostKeyFingerprint: junos.FingerprintSHA256(),
			AdminUser: "netadmin", PasswordRef: writeServedCredentialFile(t, "a270-junos-admin", "junos-admin-password-1"),
			AllowedRoles: []string{"net/noc"}, RoleBindings: map[string]string{"net/noc": "noc"}, MaxTTL: "1h", AllowStaticRotation: true},
	}
	if err = config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	for name, mutate := range map[string]func(*config.DynamicSecretProviderConfig){
		"administrator bound": func(c *config.DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"net/noc": "netadmin"} },
		"enable on junos":     func(c *config.DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"net/noc": "enable"} },
		"no host key pin":     func(c *config.DynamicSecretProviderConfig) { c.HostKeyFingerprint = "" },
		"leases":              func(c *config.DynamicSecretProviderConfig) { c.AllowStaticRotation = false },
	} {
		bad := configs[1]
		bad.RoleBindings = map[string]string{"net/noc": "noc"}
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
	tok := seedScopedTokenSubject(t, sh.store, sh.tenant, "a270-operator", "secrets:read", "secrets:write", "access:read", "access:targets.write")

	seed := func(key, host, username, password string) {
		t.Helper()
		value, _ := json.Marshal(map[string]string{"host": host, "username": username, "password": password})
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", tok, "a270-seed-"+key,
			map[string]any{"name": key, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed %s: %d %s", key, status, body)
		}
	}
	seed("net/ops", iosxe.Addr(), "ops", "ops-password-1")
	seed("net/enable", iosxe.Addr(), "enable", "enable-secret-1")
	seed("net/noc", junos.Addr(), "noc", "noc-password-1")

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
	stored := func(key string) (string, string) {
		t.Helper()
		status, body := secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/store/"+key, tok, nil)
		var view struct {
			Value string `json:"value"`
		}
		var credential struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || json.Unmarshal([]byte(view.Value), &credential) != nil {
			t.Fatalf("read %s: %d", key, status)
		}
		return credential.Username, credential.Password
	}
	signsIn := func(d *netdevicetest.Device, user, password string) bool {
		t.Helper()
		target := crypto.SSHAccountTarget{Address: d.Addr(), HostKeyFingerprint: d.FingerprintSHA256()}
		return crypto.VerifySSHAccountPassword(ctx, target, user, []byte(password)) == nil
	}

	// A device account rotates in place, so the request must acknowledge it.
	ops := map[string]any{"provider": "core-iosxe", "key": "net/ops", "old_ref": "ops"}
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/rotations", tok, "a270-unacknowledged", ops); status != http.StatusBadRequest ||
		!strings.Contains(string(body), "rotates in a single phase") {
		t.Fatalf("an unacknowledged device rotation: %d %s", status, body)
	}
	if !signsIn(iosxe, "ops", "ops-password-1") {
		t.Fatal("a refused rotation touched the device")
	}
	ops["acknowledge_single_phase"] = true
	writes := iosxe.Writes()
	view := run("a270-ops-1", ops)
	if view.Phase != "completed" || view.RotationPhase != "single_phase" || view.VerifyMode != "authenticated" || !view.CredentialValid {
		t.Fatalf("the IOS-XE account rotation: %+v", view)
	}
	user, rotated := stored("net/ops")
	if user != "ops" || string(iosxe.Password("ops")) != rotated || !signsIn(iosxe, "ops", rotated) {
		t.Fatal("the published password does not sign in on the device")
	}
	if signsIn(iosxe, "ops", "ops-password-1") {
		t.Fatal("the old password still signs in after the rotation")
	}
	if iosxe.Role("ops") != "privilege 7" || iosxe.Writes() <= writes {
		t.Fatalf("the rotation changed the account's privilege (%q) or did not save the configuration", iosxe.Role("ops"))
	}

	view = run("a270-enable-1", map[string]any{"provider": "core-iosxe", "key": "net/enable", "old_ref": "enable", "acknowledge_single_phase": true})
	if view.Phase != "completed" || view.VerifyMode != "authenticated" {
		t.Fatalf("the enable secret rotation: %+v", view)
	}
	if _, enable := stored("net/enable"); enable == "enable-secret-1" || string(iosxe.EnableSecret()) != enable {
		t.Fatal("the device's enable secret is not the published one")
	}

	view = run("a270-noc-1", map[string]any{"provider": "edge-junos", "key": "net/noc", "old_ref": "noc", "acknowledge_single_phase": true})
	if view.Phase != "completed" || view.VerifyMode != "authenticated" {
		t.Fatalf("the Junos account rotation: %+v", view)
	}
	_, noc := stored("net/noc")
	if !signsIn(junos, "noc", noc) || signsIn(junos, "noc", "noc-password-1") || junos.Role("noc") != "operator" {
		t.Fatal("the Junos account did not move to the published password alone")
	}

	// Rollback: the device reports the change but keeps the old password.
	junos.DropNextChanges(1)
	view = run("a270-noc-2", map[string]any{"provider": "edge-junos", "key": "net/noc", "old_ref": "noc", "acknowledge_single_phase": true})
	if view.Phase != "rolled_back" {
		t.Fatalf("an unverified device change was not rolled back: %+v", view)
	}
	if _, restored := stored("net/noc"); restored != noc || !signsIn(junos, "noc", noc) {
		t.Fatal("the rollback did not leave the predecessor published and signing in")
	}

	// Discovery: each device's local accounts with privilege or class.
	discovered := map[string]string{}
	for _, provider := range []string{"core-iosxe", "edge-junos"} {
		if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/discovery/sources/"+provider, tok, "a270-source-"+provider,
			map[string]any{"interval_seconds": 3600}); status != http.StatusOK && status != http.StatusCreated {
			t.Fatalf("save the %s discovery source: %d %s", provider, status, body)
		}
		status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/discovery/sources/"+provider+"/runs", tok, "a270-scan-"+provider, nil)
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
	for account, want := range map[string]string{"core-iosxe/ops": "privilege 7", "core-iosxe/netadmin": "privilege 15",
		"edge-junos/noc": "class operator", "edge-junos/netadmin": "class super-user"} {
		if discovered[account] != want {
			t.Fatalf("discovered %s = %q, want %q (all %v)", account, discovered[account], want, discovered)
		}
	}

	secrets := [][]byte{[]byte(rotated), []byte(noc), []byte("ops-password-1"), []byte("noc-password-1"), []byte("iosxe-admin-password-1"),
		[]byte("junos-admin-password-1"), []byte("$9$"), []byte("$6$")}
	defer func() {
		for _, s := range secrets {
			secret.Wipe(s)
		}
	}()
	if err = sh.log.Replay(ctx, 0, func(event events.Event) error {
		for _, s := range secrets {
			if event.TenantID == sh.tenant && bytes.Contains(event.Data, s) {
				t.Fatalf("a device password or hash reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// a270StaticRotationDue makes the tenant's pending static rotation steps due,
// so a verification that fails reaches its last attempt without the backoff.
func a270StaticRotationDue(t *testing.T, h *servedHarness) {
	t.Helper()
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE outbox SET next_attempt_at = now()
			WHERE tenant_id = $1 AND destination = 'secret.static-rotation' AND status = 'pending'`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
