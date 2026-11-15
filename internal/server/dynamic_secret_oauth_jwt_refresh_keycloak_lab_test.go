// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// A239-L7 against a stock authorization server: Keycloak, configured by
// scripts/labs/keycloak-oauth.sh. Realm "lab" has the client
// "trstctl-leases-jwt", which authenticates with a JWT signed by the key the
// script generated (Keycloak's client-jwt; no client secret), and the user
// "orders-bot"; the client's service account and the user may read the realm
// through the admin API. The test first obtains the user's refresh token once
// (the password grant, standing in for whatever grant an operator uses). A
// provider with client_auth private_key_jwt and that token as its
// refresh_token_ref then leases a reader token drawn with the refresh token,
// narrowed to orders.read, and a writer token by client credentials; stock
// curl reads the realm with each. Revoking the reader lease revokes its token
// at Keycloak's RFC 7009 endpoint, after which curl is refused, and the next
// reader lease still draws on the refresh token.
func TestServedDynamicOAuthJWTClientAndRefreshRoleByKeycloakA239L7(t *testing.T) {
	base := os.Getenv("TRSTCTL_A239L7_KEYCLOAK_URL")
	keyFile := os.Getenv("TRSTCTL_A239L7_KEYCLOAK_KEY_FILE")
	userFile := os.Getenv("TRSTCTL_A239L7_KEYCLOAK_USER_PASSWORD_FILE")
	if base == "" || keyFile == "" || userFile == "" {
		t.Skip("lab test: scripts/labs/keycloak-oauth.sh starts Keycloak and sets TRSTCTL_A239L7_KEYCLOAK_URL, _KEY_FILE and _USER_PASSWORD_FILE")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl is required: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	userPassword, err := os.ReadFile(userFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	realm := base + "/realms/lab/protocol/openid-connect"
	const client = "trstctl-leases-jwt"

	// The operator's one-time grant: orders-bot's refresh token, the client
	// authenticated by a JWT it signs, as RFC 7523 describes.
	jti, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	assertion, err := crypto.SignJWTWithPEMKeyBytes(keyPEM, "", map[string]any{
		"iss": client, "sub": client, "aud": realm + "/token", "jti": hex.EncodeToString(jti), "iat": now, "exp": now + 60})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.PostForm(realm+"/token", url.Values{ // #nosec G107,G704 -- the runner's loopback lab URL (CWE-918)
		"grant_type": {"password"}, "username": {"orders-bot"}, "password": {strings.TrimSpace(string(userPassword))},
		"scope": {"orders.read orders.write"}, "client_id": {client},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {string(assertion)}})
	if err != nil {
		t.Fatal(err)
	}
	granted, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	var grant struct {
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(granted, &grant) != nil || grant.RefreshToken == "" {
		t.Fatalf("the one-time grant: HTTP %d", resp.StatusCode)
	}

	const tenant = "a2390017-39a7-4a39-8a39-0000a2390017"
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: tenant, ID: "keycloak-jwt", Type: "oauth-client-credentials", Endpoint: realm + "/token",
		RevocationEndpoint: realm + "/revoke", ClientID: client, ClientAuth: "private_key_jwt",
		PrivateKeyRef:   writeServedCredentialFile(t, "keycloak-client-key", string(keyPEM)),
		RefreshTokenRef: writeServedCredentialFile(t, "keycloak-refresh", grant.RefreshToken), RefreshTokenRoles: []string{"reader"},
		AllowedRoles: []string{"reader", "writer"}, RoleBindings: map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"},
		MaxTTL: "5m", AllowInsecureLoopback: true,
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenantID(t, h, tenant, "A239-L7 Keycloak tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, tenant, "secrets:read", "secrets:write")

	issue := func(role, key, wantScope string) (dynamicLeaseView, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, key,
			map[string]any{"provider": "keycloak-jwt", "role": role, "ttl_seconds": 60})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("issue a %s lease: %d %s", role, status, body)
		}
		if strings.Contains(string(body), grant.RefreshToken) || strings.Contains(string(body), "PRIVATE KEY") {
			t.Fatalf("the %s lease response carries the refresh token or the client key", role)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode the %s lease: %v %s", role, err, body)
		}
		var credential map[string]any
		if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil {
			t.Fatal(err)
		}
		access, _ := credential["access_token"].(string)
		scope, _ := credential["scope"].(string)
		// Keycloak lists a token's scopes in its own order.
		got, want := strings.Fields(scope), strings.Fields(wantScope)
		slices.Sort(got)
		slices.Sort(want)
		if _, ok := credential["refresh_token"]; ok || access == "" || !slices.Equal(got, want) {
			t.Fatalf("the %s credential has scope %q (refresh token present: %v)", role, scope, ok)
		}
		return lease, access
	}
	// Stock curl is the client: the admin API's realm read needs a valid token.
	curl := func(token string) string {
		t.Helper()
		out, err := exec.Command("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", // #nosec G204,G702 -- fixed tool, lab URL and the leased token (CWE-78)
			"-H", "Authorization: Bearer "+token, base+"/admin/realms/lab").Output()
		if err != nil {
			t.Fatalf("curl: %v", err)
		}
		return strings.TrimSpace(string(out))
	}

	reader, readerToken := issue("reader", "a239l7-keycloak-lease-1", "orders.read")
	if code := curl(readerToken); code != "200" {
		t.Fatalf("Keycloak refused the reader lease's token (drawn with the refresh token): HTTP %s", code)
	}
	_, writerToken := issue("writer", "a239l7-keycloak-lease-2", "orders.read orders.write")
	if code := curl(writerToken); code != "200" {
		t.Fatalf("Keycloak refused the writer lease's token (client credentials, signed JWT): HTTP %s", code)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+reader.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(60 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+reader.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if code := curl(readerToken); code != "401" {
		t.Fatalf("Keycloak accepts the revoked reader token: HTTP %s", code)
	}
	next, nextToken := issue("reader", "a239l7-keycloak-lease-3", "orders.read")
	if code := curl(nextToken); code != "200" {
		t.Fatalf("after a revocation the refresh token no longer serves a reader lease: HTTP %s", code)
	}
	t.Logf("A239L7_KEYCLOAK_OK reader=%s next=%s granted=%q", reader.ID, next.ID, grant.Scope)
}
