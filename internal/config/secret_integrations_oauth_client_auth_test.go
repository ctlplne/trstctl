// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// TestValidateOAuthClientAuthAndRefreshRolesA239L7: an oauth-client-credentials
// provider authenticates with client_secret_basic (client_secret_ref, the
// default) or private_key_jwt (private_key_ref, with an optional client_key_id),
// never both and nothing else; refresh_token_roles name allowed roles once each
// and need refresh_token_ref, which needs them; the four fields belong to
// oauth-client-credentials alone.
func TestValidateOAuthClientAuthAndRefreshRolesA239L7(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders-api", Type: "oauth-client-credentials",
		Endpoint: "https://login.example/realms/lab/protocol/openid-connect/token", ClientID: "trstctl-leases",
		ClientAuth: "private_key_jwt", PrivateKeyRef: "file:/run/secrets/oauth-client-key", ClientKeyID: "trstctl-leases-1",
		AllowedRoles: []string{"reader", "writer"}, MaxTTL: "30m", RefreshTokenRoles: []string{"writer"},
		RefreshTokenRef: "file:/run/secrets/oauth-refresh",
		RoleBindings:    map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"}}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatalf("private_key_jwt with a refresh-token role: %v", err)
	}
	basic := base
	basic.ClientAuth, basic.PrivateKeyRef, basic.ClientKeyID, basic.ClientSecretRef = "client_secret_basic", "", "", "file:/run/secrets/oauth-client"
	if err := check(basic); err != nil {
		t.Fatalf("client_secret_basic named: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"jwt without its key":     {func(c *DynamicSecretProviderConfig) { c.PrivateKeyRef = "" }, "private_key_ref (the client's private key for private_key_jwt)"},
		"jwt with a secret too":   {func(c *DynamicSecretProviderConfig) { c.ClientSecretRef = "file:/run/secrets/oauth-client" }, "client_secret_ref is for client_auth client_secret_basic"},
		"spaced key id":           {func(c *DynamicSecretProviderConfig) { c.ClientKeyID = " trstctl-leases-1" }, "client_key_id has surrounding spaces"},
		"control in key id":       {func(c *DynamicSecretProviderConfig) { c.ClientKeyID = "k\x00" }, "client_key_id has surrounding spaces or control characters"},
		"another method":          {func(c *DynamicSecretProviderConfig) { c.ClientAuth = "client_secret_post" }, `client_auth "client_secret_post" is client_secret_basic or private_key_jwt`},
		"a spaced method":         {func(c *DynamicSecretProviderConfig) { c.ClientAuth = " private_key_jwt" }, `client_auth " private_key_jwt" is client_secret_basic or private_key_jwt`},
		"refresh role twice":      {func(c *DynamicSecretProviderConfig) { c.RefreshTokenRoles = []string{"writer", "writer"} }, `refresh_token_roles lists "writer" twice`},
		"refresh role not a role": {func(c *DynamicSecretProviderConfig) { c.RefreshTokenRoles = []string{"admin"} }, `refresh_token_roles["admin"] has no matching allowed role`},
		"refresh roles, no token": {func(c *DynamicSecretProviderConfig) { c.RefreshTokenRef = "" }, "refresh_token_ref (the refresh token refresh_token_roles draw on)"},
		"relative token file":     {func(c *DynamicSecretProviderConfig) { c.RefreshTokenRef = "file:oauth-refresh" }, "refresh_token_ref (the refresh token refresh_token_roles draw on): file reference must contain an absolute path"},
		"token, no roles":         {func(c *DynamicSecretProviderConfig) { c.RefreshTokenRoles = nil }, "refresh_token_ref is set but no refresh_token_roles draw on it"},
	} {
		c := base
		c.RefreshTokenRoles = append([]string(nil), base.RefreshTokenRoles...)
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	for name, mutate := range map[string]func(*DynamicSecretProviderConfig){
		"basic with a key":    func(c *DynamicSecretProviderConfig) { c.PrivateKeyRef = "file:/run/secrets/oauth-client-key" },
		"basic with a key id": func(c *DynamicSecretProviderConfig) { c.ClientKeyID = "trstctl-leases-1" },
	} {
		c := basic
		mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), "private_key_ref and client_key_id are for client_auth private_key_jwt") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*DynamicSecretProviderConfig){
		"client_auth":         func(c *DynamicSecretProviderConfig) { c.ClientAuth = "private_key_jwt" },
		"client_key_id":       func(c *DynamicSecretProviderConfig) { c.ClientKeyID = "k1" },
		"refresh_token_roles": func(c *DynamicSecretProviderConfig) { c.RefreshTokenRoles = []string{"operator"} },
		"refresh_token_ref":   func(c *DynamicSecretProviderConfig) { c.RefreshTokenRef = "file:/run/secrets/oauth-refresh" },
	} {
		other := DynamicSecretProviderConfig{TenantID: base.TenantID, ID: "totp", Type: "totp", SeedRef: "file:/run/secrets/totp-seed",
			AllowedRoles: []string{"operator"}, MaxTTL: "30s"}
		mutate(&other)
		if err := check(other); err == nil || !strings.Contains(err.Error(), "client_auth, client_key_id, refresh_token_ref and refresh_token_roles are only valid for oauth-client-credentials") {
			t.Errorf("%s on a totp provider: %v", name, err)
		}
	}
}
