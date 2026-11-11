// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
)

// DEV-D1: a privileged-account scan of a server management controller or a
// network device says why it could not sign in. With the wrong administrator
// password a Redfish controller's scan and an IOS-XE switch's scan (over SSH)
// fail as rejected, so an operator fixes the stored password; once the devices
// stop answering, the same scans fail as unreachable, so they look at the
// network. Before, every one of these read as a plain error.
func TestServedDeviceScansNameWhyTheyCouldNotSignInDEVD1(t *testing.T) {
	bmc := infratest.StartRedfish("Administrator", "devd1-bmc-admin-password")
	t.Cleanup(bmc.Close)
	sw, err := netdevicetest.Start(netdevicetest.IOSXE, "netadmin", "devd1-iosxe-admin-password", "privilege 15")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sw.Close)
	configs := []config.DynamicSecretProviderConfig{
		{TenantID: servedTestTenant, ID: "devd1-bmc", Type: "redfish", Endpoint: bmc.URL(),
			TLSCARef: writeServedCredentialFile(t, "devd1-bmc-ca", string(bmc.CAPEM())), AllowPrivate: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"},
			AdminUser: "Administrator", PasswordRef: writeServedCredentialFile(t, "devd1-bmc-admin", "not-the-bmc-password"),
			AllowedRoles: []string{"bmc/ops"}, RoleBindings: map[string]string{"bmc/ops": "ops"}, MaxTTL: "1h", AllowStaticRotation: true},
		{TenantID: servedTestTenant, ID: "devd1-iosxe", Type: "iosxe", Addr: sw.Addr(), HostKeyFingerprint: sw.FingerprintSHA256(),
			AdminUser: "netadmin", PasswordRef: writeServedCredentialFile(t, "devd1-iosxe-admin", "not-the-switch-password"),
			AllowedRoles: []string{"net/ops"}, RoleBindings: map[string]string{"net/ops": "ops"}, MaxTTL: "1h", AllowStaticRotation: true},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	tok := seedScopedTokenSubject(t, sh.store, sh.tenant, "devd1-operator", "secrets:read", "secrets:write", "access:read", "access:targets.write")
	scan := func(provider, key string) a260Run {
		t.Helper()
		if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/discovery/sources/"+provider, tok, key+"-source",
			map[string]any{"interval_seconds": 3600}); status != http.StatusOK && status != http.StatusCreated {
			t.Fatalf("save the discovery source %s: %d %s", provider, status, body)
		}
		status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/discovery/sources/"+provider+"/runs", tok, key+"-scan", nil)
		var queued a260Run
		if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil {
			t.Fatalf("scan %s: %d %s", provider, status, body)
		}
		return awaitQueuedDiscoveryProofA267(t, sh, tok, queued.ID)
	}

	for _, provider := range []string{"devd1-bmc", "devd1-iosxe"} {
		if run := scan(provider, provider+"-wrong"); run.Status != "failed" || run.Failure != "rejected" || run.Accounts != 0 {
			t.Errorf("%s with the wrong administrator password: %+v, want failed as rejected", provider, run)
		}
	}
	bmc.Close()
	sw.Close()
	for _, provider := range []string{"devd1-bmc", "devd1-iosxe"} {
		if run := scan(provider, provider+"-gone"); run.Status != "failed" || run.Failure != "unreachable" || run.Accounts != 0 {
			t.Errorf("%s that does not answer: %+v, want failed as unreachable", provider, run)
		}
	}
}
