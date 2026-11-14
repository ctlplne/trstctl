// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// TestServedDirectoryAccountHealthNeverLocksOutA258L1 is A258-L1's Done-when
// (served, Active Directory stand-in, domain lockout threshold 3): a remote
// desktop target whose vaulted account is an Active Directory account (A263)
// is checked by A258's health worker through its provider's lockout-aware
// check. An operator's first check reads healthy. The password changed at the
// directory reads rejected once and is not retried. Someone else's failed
// sign-ins bring the account one short of lockout: an operator's check now
// and every scheduled check read lockout_risk (not "not retried": the count is
// read again each time) and sign in with nothing, so the account never locks.
// Once the count clears and the vault holds the directory's password the next
// check reads healthy; a locked account reads locked without a sign-in. Each
// status is what GET /api/v1/access/targets/rdp/<id> serves.
func TestServedDirectoryAccountHealthNeverLocksOutA258L1(t *testing.T) {
	ctx := context.Background()
	const (
		accountDN = "CN=svc-desktop-a258l1,OU=Trstctl,DC=corp,DC=test"
		adminDN   = "CN=Rotator,CN=Users,DC=corp,DC=test"
		role      = "desktop/a258l1"
		target    = "a258l1-desktop"
	)
	adminPassword := "Tr5!rotator-" + "owned-fixture"
	first := "Tr5!vaulted-" + "owned-fixture"
	changed := "Tr5!changed-" + "at-the-directory"
	directory, err := infratest.StartAD("DC=corp,DC=test", 3, adminDN, []byte(adminPassword))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(directory.Close)
	directory.AddAccount(accountDN, "svc-desktop-a258l1", []byte(first))

	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "a258l1-ad", Type: "ldap", DirectoryMode: "active_directory",
		Addr: directory.Addr(), TLSServerName: infratest.ADServerName, TLSCARef: writeServedCredentialFile(t, "a258l1-ad-ca", string(directory.CAPEM())),
		BindDN: adminDN, PasswordRef: writeServedCredentialFile(t, "a258l1-ad-admin", adminPassword), UsersDN: "OU=Trstctl,DC=corp,DC=test",
		AllowedRoles: []string{role}, RoleBindings: map[string]string{role: accountDN}, ADLogonNames: map[string]string{accountDN: "svc-desktop-a258l1"},
		AllowStaticRotation: true, MaxTTL: "1h"}
	if err := json.Unmarshal([]byte(`{"desktop":{"address":"127.0.0.1:3389","certificate_sha256":"`+strings.Repeat("ab", 32)+`","width":800,"height":600,"tls_only":true}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second, HealthInterval: time.Hour,
			Attestors: []attest.Attestor{servedPAMAttestor{}},
			DatabaseTargets: []PAMDatabaseTarget{{TargetType: pamTargetRDP, TenantID: servedTestTenant, ID: target, ProviderID: "a258l1-ad",
				AllowedRoles: []string{role}, AccountSecret: role, GatewayAgentID: agentRowID(servedTestTenant, "role-agent"), GatewayAddress: "127.0.0.1:1"}}}
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a258l1-operator", "access:read", "access:targets.write", "secrets:read", "secrets:write")
	vault := func(password string) {
		t.Helper()
		value, err := json.Marshal(struct { // #nosec G117 -- a test's own fixture credential, to the encrypted secret store (CWE-200)
			BindDN   string           `json:"bind_dn"`
			Username string           `json:"username"`
			Password secret.JSONBytes `json:"password"`
		}{accountDN, "svc-desktop-a258l1", []byte(password)})
		if err != nil {
			t.Fatal(err)
		}
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", operator, "a258l1-vault-"+password,
			map[string]any{"name": role, "value": string(value)})
		if status == http.StatusConflict {
			status, body = secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/secrets/store/"+role, operator, "a258l1-rotate-"+password,
				map[string]any{"value": string(value)})
		}
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("vault the account: %d %s", status, body)
		}
	}
	type health struct {
		Status     string `json:"status"`
		NotRetried bool   `json:"not_retried"`
	}
	read := func() health {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/targets/rdp/"+target, operator, nil)
		var view struct {
			Health *health `json:"health"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || view.Health == nil {
			t.Fatalf("read the target = %d %s", status, body)
		}
		return *view.Health
	}
	expect := func(step string, want health, signIns, bad int) {
		t.Helper()
		if got := read(); got != want || directory.SignIns(accountDN) != signIns || directory.BadPwdCount(accountDN) != bad {
			t.Fatalf("%s: reads %+v after %d sign-ins as the account (badPwdCount %d, locked %v); want %+v, %d and %d",
				step, got, directory.SignIns(accountDN), directory.BadPwdCount(accountDN), directory.Locked(accountDN), want, signIns, bad)
		}
	}
	vault(first)

	// An operator's first check signs in with the vaulted password.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets/rdp/"+target+"/health-check", operator, "a258l1-check-now", nil); status != http.StatusOK || !strings.Contains(string(body), `"status":"healthy"`) {
		t.Fatalf("check now = %d %s", status, body)
	}
	expect("the vaulted password", health{"healthy", false}, 1, 0)

	accounts, err := h.srv.pam.healthAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var account pamHealthAccount
	for _, a := range accounts {
		if a.tenantID == servedTestTenant && a.targetType == pamTargetRDP && a.targetID == target {
			account = a
		}
	}
	if account.accountSecret != role {
		t.Fatalf("the health worker lists the desktop account as %+v; want its vaulted secret %s", account, role)
	}

	// Changed at the directory: rejected once, never tried again unchanged.
	directory.SetPassword(accountDN, []byte(changed))
	h.srv.pam.checkAccount(ctx, account, false)
	expect("the password changed at the directory", health{"rejected", true}, 2, 1)
	for i := 0; i < 3; i++ {
		h.srv.pam.checkAccount(ctx, account, false)
	}
	expect("three more scheduled checks", health{"rejected", true}, 2, 1)

	// Someone else's wrong passwords bring the account one short of lockout.
	// An operator's check (which tries even a refused password again) and the
	// scheduled checks read the count, and sign in with nothing.
	directory.SetBadPwdCount(accountDN, 2)
	h.srv.pam.checkAccount(ctx, account, true)
	expect("an operator's check one short of lockout", health{"lockout_risk", false}, 2, 2)
	for i := 0; i < 5; i++ {
		h.srv.pam.checkAccount(ctx, account, false)
	}
	expect("five scheduled checks one short of lockout", health{"lockout_risk", false}, 2, 2)
	if directory.Locked(accountDN) {
		t.Fatal("the checks locked the account")
	}

	// The count clears and the vault holds the directory's password.
	directory.SetBadPwdCount(accountDN, 0)
	vault(changed)
	h.srv.pam.checkAccount(ctx, account, false)
	expect("the vault's new password", health{"healthy", false}, 3, 0)

	// Locked elsewhere: read from the account's state, no sign-in.
	directory.Lock(accountDN)
	h.srv.pam.checkAccount(ctx, account, false)
	expect("a locked account", health{"locked", true}, 3, 0)
	t.Logf("A258L1_OK sign_ins=%d statuses=healthy,rejected,lockout_risk,healthy,locked", directory.SignIns(accountDN))
}
