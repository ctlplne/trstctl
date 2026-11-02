// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A239 against a stock authorization server: Keycloak, configured by the A239
// runner (a realm "lab" with the confidential client "trstctl-leases", whose
// service account may read the realm through the admin API). A lease is a token
// with only the role's scope; stock curl reads the realm with it; the lease
// can't be extended; revoking it revokes the token at Keycloak's RFC 7009
// endpoint, after which curl is refused.
func TestServedDynamicOAuthLeaseRevokedByKeycloakA239(t *testing.T) {
	base := os.Getenv("TRSTCTL_A239_KEYCLOAK_URL")
	secretFile := os.Getenv("TRSTCTL_A239_KEYCLOAK_SECRET_FILE")
	if base == "" || secretFile == "" {
		t.Skip("lab test: the A239 runner starts Keycloak and sets TRSTCTL_A239_KEYCLOAK_URL and TRSTCTL_A239_KEYCLOAK_SECRET_FILE")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl is required: %v", err)
	}
	clientSecret, err := os.ReadFile(secretFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	realm := base + "/realms/lab/protocol/openid-connect"
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "keycloak-lab", Type: "oauth-client-credentials",
		Endpoint: realm + "/token", RevocationEndpoint: realm + "/revoke", ClientID: "trstctl-leases",
		ClientSecretRef: writeServedCredentialFile(t, "keycloak-client", strings.TrimSpace(string(clientSecret))),
		AllowedRoles:    []string{"reader"}, RoleBindings: map[string]string{"reader": "orders.read"},
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
	registerServedTenant(t, h, "A239 Keycloak tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-keycloak-lease-1",
		map[string]any{"provider": "keycloak-lab", "role": "reader", "ttl_seconds": 60})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		AccessToken string    `json:"access_token"`
		Scope       string    `json:"scope"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.AccessToken == "" || credential.Scope != "orders.read" {
		t.Fatalf("credential scope %q (%v)", credential.Scope, err)
	}
	// Stock curl is the client: the admin API's realm read needs a valid token.
	curl := func() string {
		t.Helper()
		out, err := exec.Command("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", // #nosec G204,G702 -- fixed tool, lab URL and the leased token (CWE-78)
			"-H", "Authorization: Bearer "+credential.AccessToken, base+"/admin/realms/lab").Output()
		if err != nil {
			t.Fatalf("curl: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if code := curl(); code != "200" {
		t.Fatalf("Keycloak refused the leased token before revocation: HTTP %s", code)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 10})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "can't be extended") {
		t.Fatalf("an access token was extended: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(60 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if code := curl(); code != "401" {
		t.Fatalf("Keycloak accepts the revoked token: HTTP %s", code)
	}
	t.Logf("A239_OAUTH_KEYCLOAK_OK lease=%s scope=%s token_expires_at=%s", lease.ID, credential.Scope, credential.ExpiresAt.Format(time.RFC3339))
}
