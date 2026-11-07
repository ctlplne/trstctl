// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
)

// TestServedAccountCheckoutA271: an ESXi local account, a vCenter single
// sign-on user, a Redfish controller account and a network device account,
// each vaulted in an application secret its provider rotates in place, are
// registered as account targets and checked out through A261: reviewed,
// revealed once, never opened as a session. Checking one in queues its
// provider's in-place rotation; when it completes the revealed password no
// longer signs in at the target and the vault holds the new one. An account
// target is refused for a role its provider does not rotate in place.
func TestServedAccountCheckoutA271(t *testing.T) {
	ctx := context.Background()
	// A tenant of its own: the package's served tests share servedTestTenant,
	// and other check-out tests count every check-out in it.
	tenant := uuid.NewString()
	esxi := infratest.StartESXi("root", "esxi-root-password-1")
	t.Cleanup(esxi.Close)
	esxi.AddAccount("ops", "esxi-ops-password-1", -1)
	vc, err := infratest.StartVCenter("vsphere.local", "sso-admin-password-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vc.Close)
	vc.AddUser("svc-backup", "sso-backup-password-1", true)
	bmc := infratest.StartRedfish("Administrator", "bmc-admin-password-1")
	t.Cleanup(bmc.Close)
	bmc.AddAccount("ops", "bmc-ops-password-1", "Operator")
	router, err := netdevicetest.Start(netdevicetest.IOSXE, "netadmin", "router-admin-password-1", "privilege 15")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	router.AddAccount("ops", "router-ops-password-1", "privilege 15")

	private := func(c config.DynamicSecretProviderConfig) config.DynamicSecretProviderConfig {
		c.TenantID, c.MaxTTL, c.AllowStaticRotation = tenant, "1h", true
		c.AllowPrivate, c.PrivateEgressCIDRs = true, []string{"127.0.0.1/32"}
		return c
	}
	configs := []config.DynamicSecretProviderConfig{
		private(config.DynamicSecretProviderConfig{ID: "esxi-host", Type: "esxi", Endpoint: esxi.URL(),
			TLSCARef: writeServedCredentialFile(t, "a271co-esxi-ca", string(esxi.CAPEM())), AdminUser: "root",
			PasswordRef:  writeServedCredentialFile(t, "a271co-esxi-admin", "esxi-root-password-1"),
			AllowedRoles: []string{"esxi/ops"}, RoleBindings: map[string]string{"esxi/ops": "ops"}}),
		private(config.DynamicSecretProviderConfig{ID: "vcenter", Type: "vcenter-sso", Endpoint: vc.URL(),
			TLSCARef: writeServedCredentialFile(t, "a271co-vc-ca", string(vc.CAPEM())), Addr: vc.SSHAddr(), HostKeyFingerprint: vc.FingerprintSHA256(),
			AdminUser: "root", PrivateKeyRef: writeServedCredentialFile(t, "a271co-vc-root", string(vc.RootKeyPKCS8())), SSOAdmin: "administrator@vsphere.local",
			PasswordRef:  writeServedCredentialFile(t, "a271co-vc-admin", "sso-admin-password-1"),
			AllowedRoles: []string{"sso/backup"}, RoleBindings: map[string]string{"sso/backup": "svc-backup"}}),
		private(config.DynamicSecretProviderConfig{ID: "rack-bmc", Type: "redfish", Endpoint: bmc.URL(),
			TLSCARef: writeServedCredentialFile(t, "a271co-bmc-ca", string(bmc.CAPEM())), AdminUser: "Administrator",
			PasswordRef:  writeServedCredentialFile(t, "a271co-bmc-admin", "bmc-admin-password-1"),
			AllowedRoles: []string{"bmc/ops"}, RoleBindings: map[string]string{"bmc/ops": "ops"}}),
		{TenantID: tenant, ID: "core-router", Type: "iosxe", Addr: router.Addr(), HostKeyFingerprint: router.FingerprintSHA256(),
			AdminUser: "netadmin", PasswordRef: writeServedCredentialFile(t, "a271co-router-admin", "router-admin-password-1"),
			AllowedRoles: []string{"net/ops"}, RoleBindings: map[string]string{"net/ops": "ops"}, MaxTTL: "1h", AllowStaticRotation: true},
	}
	if err = config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: registry.ForTenant(tenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	registerServedTenantID(t, sh, tenant, "A271 account check-outs")
	custodian := seedScopedTokenSubject(t, sh.store, tenant, "a271co-custodian", "access:read", "access:targets.write", "secrets:read", "secrets:write")
	requester := seedScopedTokenSubject(t, sh.store, tenant, "a271co-requester", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, sh.store, tenant, "a271co-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, sh.store, tenant, "a271co-reviewer-2", "access:read", "access:approve"),
	}

	type account struct {
		target, provider, secret, username, initial string
		signsIn                                     func(password string) bool
	}
	accounts := []account{
		{"esxi-ops", "esxi-host", "esxi/ops", "ops", "esxi-ops-password-1", func(p string) bool { return esxi.SignsIn("ops", p) }},
		{"vc-backup", "vcenter", "sso/backup", "svc-backup@vsphere.local", "sso-backup-password-1", func(p string) bool { return vc.SignsIn("svc-backup", p) }},
		{"bmc-ops", "rack-bmc", "bmc/ops", "ops", "bmc-ops-password-1", func(p string) bool { return bmc.SignsIn("ops", p) }},
		{"router-ops", "core-router", "net/ops", "ops", "router-ops-password-1", func(p string) bool {
			return string(router.Password("ops")) == p
		}},
	}
	register := func(key string, body map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/targets", custodian, key, body)
	}
	for _, a := range accounts {
		value, _ := json.Marshal(map[string]string{"username": a.username, "password": a.initial})
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", custodian, "a271co-seed-"+a.target,
			map[string]any{"name": a.secret, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed %s: %d %s", a.secret, status, body)
		}
		if status, body := register("a271co-register-"+a.target, map[string]any{"id": a.target, "target_type": "account",
			"provider_id": a.provider, "account_secret": a.secret}); status != http.StatusCreated || !strings.Contains(string(body), `"target_type":"account"`) {
			t.Fatalf("register %s = %d %s", a.target, status, body)
		}
	}
	if status, body := register("a271co-wrong-role", map[string]any{"id": "esxi-other", "target_type": "account", "provider_id": "esxi-host",
		"account_secret": "esxi/other"}); status == http.StatusCreated {
		t.Fatalf("an account target for a role its provider does not rotate was registered: %s", body)
	}
	if status, body := register("a271co-gateway", map[string]any{"id": "esxi-gw", "target_type": "account", "provider_id": "esxi-host",
		"account_secret": "esxi/ops", "gateway_agent_id": uuid.NewString(), "gateway_address": "127.0.0.1:1"}); status == http.StatusCreated {
		t.Fatalf("an account target with a gateway was registered: %s", body)
	}
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/session-requests", requester, "a271co-session",
		map[string]any{"request_id": uuid.NewString(), "target_type": "account", "target_id": "esxi-ops", "role": "esxi/ops",
			"reason": "direct session", "method": "stub_pam", "payload_base64": "Z2VudWluZQ==", "ttl_seconds": 120}); status != http.StatusUnprocessableEntity ||
		!strings.Contains(string(body), "no sessions") {
		t.Fatalf("an account session request = %d %s", status, body)
	}

	for _, a := range accounts {
		status, raw := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/checkouts", requester, "a271co-request-"+a.target,
			map[string]any{"request_id": uuid.NewString(), "target_type": "account", "target_id": a.target,
				"reason": "CHG-2711 maintenance window", "ttl_seconds": 120})
		var review struct {
			RequestID         string `json:"request_id"`
			ApprovalRequestID string `json:"approval_request_id"`
			IntentDigest      string `json:"intent_digest"`
			RequiredApprovals int    `json:"required_approvals"`
		}
		if status != http.StatusAccepted || json.Unmarshal(raw, &review) != nil || review.RequiredApprovals < 1 || review.RequiredApprovals > len(reviewers) {
			t.Fatalf("request %s = %d %s", a.target, status, raw)
		}
		for i, reviewer := range reviewers[:review.RequiredApprovals] {
			if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/approval-requests/"+review.ApprovalRequestID+"/approvals",
				reviewer, "a271co-approve-"+a.target+"-"+strconv.Itoa(i), map[string]any{"intent_digest": review.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %s %d = %d %s", a.target, i+1, status, body)
			}
		}
		status, raw = secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/checkouts/"+review.RequestID+"/reveal", requester, "a271co-reveal-"+a.target,
			map[string]any{"approval_request_id": review.ApprovalRequestID, "intent_digest": review.IntentDigest})
		var revealed struct {
			Checkout struct {
				Status string `json:"status"`
			} `json:"checkout"`
			Credential string `json:"credential"`
		}
		var shown struct {
			Password string `json:"password"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &revealed) != nil || revealed.Checkout.Status != "revealed" ||
			json.Unmarshal([]byte(revealed.Credential), &shown) != nil || shown.Password != a.initial || !a.signsIn(shown.Password) {
			t.Fatalf("reveal %s = %d", a.target, status)
		}
		status, raw = secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/checkouts/"+review.RequestID+"/checkin", requester, "a271co-checkin-"+a.target, nil)
		var checkedIn struct {
			Status            string `json:"status"`
			RotationCommandID string `json:"rotation_command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &checkedIn) != nil || checkedIn.Status != "checked_in" || checkedIn.RotationCommandID == "" {
			t.Fatalf("check in %s = %d %s", a.target, status, raw)
		}
		var view staticRotationCommandView
		for deadline := time.Now().Add(90 * time.Second); ; {
			staticRotationDueFor(t, sh, tenant)
			sh.srv.dispatchOnce(ctx)
			status, raw = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/rotations/"+checkedIn.RotationCommandID, custodian, nil)
			if status != http.StatusOK || json.Unmarshal(raw, &view) != nil {
				t.Fatalf("read %s's rotation: %d %s", a.target, status, raw)
			}
			if view.Terminal {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s's check-in rotation did not finish: %s", a.target, raw)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if view.Phase != "completed" || view.VerifyMode != "authenticated" {
			t.Fatalf("%s's check-in rotation: %+v", a.target, view)
		}
		status, raw = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/store/"+a.secret, custodian, nil)
		var vault struct {
			Value string `json:"value"`
		}
		var current struct {
			Password string `json:"password"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &vault) != nil || json.Unmarshal([]byte(vault.Value), &current) != nil ||
			current.Password == a.initial || !a.signsIn(current.Password) || a.signsIn(a.initial) {
			t.Fatalf("%s: the revealed password was not retired for the vault's new one", a.target)
		}
	}
}
