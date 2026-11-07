// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
)

// TestServedBreakGlassHealthNeverLocksOutA272: A258's health worker checks a
// break-glass account by signing in once with its vaulted password where the
// identity provider has a non-interactive check — Okta and Entra ID, whose
// MFA step after the right password counts as healthy — and reads Google
// Workspace as not supported. When the password is changed behind the
// vault's back the check reads rejected once and is never repeated with the
// same vaulted password, however many slots pass, so the account's failed
// sign-ins stay at one, far from its lockout; an operator's check now waits a
// minute after the last and, unlike a database account's, never signs in with
// the refused password either; a new vaulted password is checked again and
// reads healthy, which resets the provider's count.
func TestServedBreakGlassHealthNeverLocksOutA272(t *testing.T) {
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
		p.AddUser("breakglass@corp.example", "vaulted-password-1!", true)
	}
	idp := func(id, typ, role string) config.DynamicSecretProviderConfig {
		return config.DynamicSecretProviderConfig{TenantID: tenant, ID: id, Type: typ, AllowInsecureLoopback: true, MaxTTL: "1h", AllowStaticRotation: true,
			AllowedRoles: []string{role}, RoleBindings: map[string]string{role: "breakglass@corp.example"}}
	}
	oktaCfg := idp("okta-org", "okta-user", "bg/okta")
	oktaCfg.Endpoint, oktaCfg.APIKeyRef = okta.URL(), writeServedCredentialFile(t, "a272h-okta-token", "okta-api-token-1")
	entraCfg := idp("entra-tenant", "entra-user", "bg/entra")
	entraCfg.Endpoint, entraCfg.AuthorityHost, entraCfg.AzureTenant, entraCfg.ClientID = entra.URL(), entra.URL(), "corp-tenant", "app-client-1"
	entraCfg.ClientSecretRef = writeServedCredentialFile(t, "a272h-entra-secret", "app-secret-1")
	googleCfg := idp("workspace", "google-workspace-user", "bg/google")
	googleCfg.Endpoint, googleCfg.AuthorityHost = google.URL(), google.URL()+"/token"
	googleCfg.ServiceAccount, googleCfg.AdminUser = "rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example"
	googleCfg.PrivateKeyRef = writeServedCredentialFile(t, "a272h-google-key", string(google.ServiceAccountKeyPEM()))
	configs := []config.DynamicSecretProviderConfig{oktaCfg, entraCfg, googleCfg}
	if err = config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: registry.ForTenant(tenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second, HealthInterval: time.Hour,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	registerServedTenantID(t, sh, tenant, "A272 break-glass health")
	admin := seedScopedTokenSubject(t, sh.store, tenant, "a272h-admin", "access:read", "access:write", "access:targets.write", "secrets:read", "secrets:write")
	vault := func(name, password string) {
		t.Helper()
		value, _ := json.Marshal(map[string]string{"username": "breakglass@corp.example", "password": password})
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", admin, "a272h-vault-"+name+"-"+password,
			map[string]any{"name": name, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("vault %s: %d %s", name, status, body)
		}
	}
	health := func(target string) (string, bool) {
		t.Helper()
		status, body := secretsReq(t, sh, http.MethodGet, "/api/v1/access/targets/breakglass/"+target, admin, nil)
		var view struct {
			Health *struct {
				Status     string `json:"status"`
				NotRetried bool   `json:"not_retried"`
			} `json:"health"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || view.Health == nil {
			t.Fatalf("read %s's health = %d %s", target, status, body)
		}
		return view.Health.Status, view.Health.NotRetried
	}
	for _, a := range []struct{ target, provider, secret string }{
		{"okta-bg", "okta-org", "bg/okta"}, {"entra-bg", "entra-tenant", "bg/entra"}, {"google-bg", "workspace", "bg/google"},
	} {
		vault(a.secret, "vaulted-password-1!")
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/targets", admin, "a272h-register-"+a.target,
			map[string]any{"id": a.target, "target_type": "breakglass", "provider_id": a.provider, "account_secret": a.secret}); status != http.StatusCreated {
			t.Fatalf("register %s = %d %s", a.target, status, body)
		}
	}
	accounts, err := h.srv.pam.healthAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	find := func(target string) pamHealthAccount {
		for _, a := range accounts {
			if a.tenantID == tenant && a.targetID == target {
				return a
			}
		}
		t.Fatalf("the health worker does not list %s", target)
		return pamHealthAccount{}
	}
	for _, tc := range []struct {
		target, secret string
		idp            *infratest.IdP
		supported      bool
	}{
		{"okta-bg", "bg/okta", okta, true},
		{"entra-bg", "bg/entra", entra, true},
		{"google-bg", "bg/google", google, false},
	} {
		a := find(tc.target)
		h.srv.pam.checkAccount(ctx, a, false)
		if status, _ := health(tc.target); (tc.supported && status != "healthy") || (!tc.supported && status != "not_supported") {
			t.Fatalf("%s: the first check read %s", tc.target, status)
		}
		if !tc.supported {
			continue
		}
		// The password changes behind the vault's back.
		tc.idp.AddUser("breakglass@corp.example", "changed-elsewhere-1!", true)
		h.srv.pam.checkAccount(ctx, a, false)
		if status, notRetried := health(tc.target); status != "rejected" || !notRetried || tc.idp.Failed("breakglass@corp.example") != 1 {
			t.Fatalf("%s: a changed password read %s (not retried %v, failed %d)", tc.target, status, notRetried, tc.idp.Failed("breakglass@corp.example"))
		}
		for slot := 0; slot < 2*infratest.LockoutThreshold; slot++ {
			h.srv.pam.checkAccount(ctx, a, false)
		}
		if tc.idp.Failed("breakglass@corp.example") != 1 || tc.idp.Locked("breakglass@corp.example") {
			t.Fatalf("%s: repeated slots signed in with the refused password: failed=%d locked=%v", tc.target, tc.idp.Failed("breakglass@corp.example"), tc.idp.Locked("breakglass@corp.example"))
		}
		if status, _ := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/targets/breakglass/"+tc.target+"/health-check", admin, "a272h-now-"+tc.target, nil); status == http.StatusOK {
			t.Fatalf("%s: an operator check within a minute of the last ran", tc.target)
		}
		// Past the minute, an operator's check (now) still never signs in with
		// the refused password.
		if h.srv.pam.checkAccount(ctx, a, true) || tc.idp.Failed("breakglass@corp.example") != 1 {
			t.Fatalf("%s: an operator's check signed in with the refused password: failed=%d", tc.target, tc.idp.Failed("breakglass@corp.example"))
		}
		// The vault is repaired: a new credential is checked again.
		repaired, _ := json.Marshal(map[string]string{"username": "breakglass@corp.example", "password": "changed-elsewhere-1!"})
		if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/secrets/store/"+tc.secret, admin, "a272h-repair-"+tc.target,
			map[string]any{"value": string(repaired)}); status != http.StatusOK {
			t.Fatalf("%s: repair the vault = %d %s", tc.target, status, body)
		}
		h.srv.pam.checkAccount(ctx, a, false)
		if status, _ := health(tc.target); status != "healthy" || tc.idp.Failed("breakglass@corp.example") != 0 || tc.idp.Pending() != 0 {
			t.Fatalf("%s: after the repair the check read %s (failed %d)", tc.target, status, tc.idp.Failed("breakglass@corp.example"))
		}
	}
}
