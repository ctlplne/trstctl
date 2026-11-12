// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// OD-5 (N3-L4): a GitHub App or OAuth lease's completed revocation names how
// its token ended, as an AWS STS lease's does. A GitHub App token GitHub
// revoked when it was presented, and an OAuth token its authorization
// server's revocation endpoint revoked, are token_revoked; an OAuth token
// with no revocation endpoint stays pending until its own expiry and then
// completes as native_expiry. Each lease names whose native expiry it
// carries (github_app_token, oauth_token).
func TestServedLeaseRevocationNamesHowTheTokenEndedOD5(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := crypto.PublicJWK(signer.Public(), "")
	signer.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	_, github := newGitHubAPIStandIn(t, crypto.JWKS{Keys: []crypto.JWK{jwk}})
	lab, oauth := newOAuthLabServer(t)
	clientSecretRef := writeServedCredentialFile(t, "od5-oauth-client", "lab-client-secret")
	oauthProvider := func(id string, revocation bool) config.DynamicSecretProviderConfig {
		c := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: id, Type: "oauth-client-credentials", Endpoint: oauth.URL + "/token",
			ClientID: "trstctl-leases", ClientSecretRef: clientSecretRef, AllowedRoles: []string{"reader"},
			RoleBindings: map[string]string{"reader": "orders.read"}, MaxTTL: "5m", AllowInsecureLoopback: true,
		}
		if revocation {
			c.RevocationEndpoint = oauth.URL + "/revoke"
		}
		return c
	}
	configs := []config.DynamicSecretProviderConfig{
		{
			TenantID: servedTestTenant, ID: "github", Type: "github-app", Endpoint: github.URL, ClientID: "Iv1.served",
			PrivateKeyRef: writeServedCredentialFile(t, "od5-github-app-key", string(keyPEM)), InstallationID: "4242",
			AllowedRoles: []string{"ci"}, RoleBindings: map[string]string{"ci": "contents:read on api"},
			MaxTTL: "1h", AllowInsecureLoopback: true,
		},
		oauthProvider("orders", true), oauthProvider("orders-ttl", false),
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "OD-5 revocation method tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	type leaseView struct {
		ID               string     `json:"id"`
		RevocationStatus string     `json:"revocation_status"`
		RevocationMethod string     `json:"revocation_method"`
		NativeExpiresAt  *time.Time `json:"native_expires_at"`
		NativeExpiryKind string     `json:"native_expiry_kind"`
	}
	issue := func(provider, role, key string, ttl int) leaseView {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, key,
			map[string]any{"provider": provider, "role": role, "ttl_seconds": ttl})
		var lease leaseView
		if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &lease) != nil || lease.ID == "" {
			t.Fatalf("issue %s: %d %s", provider, status, body)
		}
		return lease
	}
	revoke := func(lease leaseView) {
		t.Helper()
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke %s: %d %s", lease.ID, status, body)
		}
	}
	read := func(id string) leaseView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+id, tok, nil)
		var view leaseView
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
			t.Fatalf("read %s: %d %s", id, status, body)
		}
		return view
	}
	completed := func(id string, within time.Duration) leaseView {
		t.Helper()
		for deadline := time.Now().Add(within); ; {
			if view := read(id); view.RevocationStatus == "completed" {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("the revocation of %s did not complete: %+v", id, read(id))
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	ghLease := issue("github", "ci", "od5-github", 1800)
	if ghLease.NativeExpiryKind != "github_app_token" || ghLease.NativeExpiresAt == nil {
		t.Fatalf("the GitHub App lease = %+v, want a github_app_token expiry", ghLease)
	}
	revoke(ghLease)
	if done := completed(ghLease.ID, 30*time.Second); done.RevocationMethod != "token_revoked" {
		t.Fatalf("the GitHub App revocation = %+v, want token_revoked", done)
	}

	oauthLease := issue("orders", "reader", "od5-oauth", 60)
	if oauthLease.NativeExpiryKind != "oauth_token" {
		t.Fatalf("the OAuth lease = %+v, want an oauth_token expiry", oauthLease)
	}
	revoke(oauthLease)
	if done := completed(oauthLease.ID, 30*time.Second); done.RevocationMethod != "token_revoked" {
		t.Fatalf("the OAuth revocation = %+v, want token_revoked", done)
	}

	// No revocation endpoint: the revocation waits for the token's own
	// expiry, then completes as native_expiry.
	lab.setLifetime(3 * time.Second)
	ttlLease := issue("orders-ttl", "reader", "od5-oauth-ttl", 2)
	revoke(ttlLease)
	if pending := read(ttlLease.ID); pending.RevocationStatus != "pending" || pending.RevocationMethod != "" || pending.NativeExpiryKind != "oauth_token" {
		t.Fatalf("the TTL-only revocation before the token's expiry = %+v, want pending", pending)
	}
	done := completed(ttlLease.ID, 45*time.Second)
	if done.RevocationMethod != "native_expiry" || done.NativeExpiresAt == nil || time.Now().Before(*done.NativeExpiresAt) {
		t.Fatalf("the TTL-only revocation = %+v, want native_expiry after the token's expiry", done)
	}
	t.Logf("OD5_REVOCATION_METHOD_OK github=%s oauth=%s ttl=%s", ghLease.ID, oauthLease.ID, ttlLease.ID)
}
