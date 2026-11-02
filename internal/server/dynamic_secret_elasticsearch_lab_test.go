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

// A239 against stock Elasticsearch, configured by the A239 runner: a
// single-node cluster with security on, index logs-lab holding one document,
// administrator elastic. A lease is an API key that stock curl can search
// logs-lab with but not write; revoking the lease invalidates the key and
// Elasticsearch refuses it.
func TestServedDynamicElasticsearchKeyAgainstElasticsearchA239(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A239_ELASTICSEARCH_URL")
	passwordFile := os.Getenv("TRSTCTL_A239_ELASTICSEARCH_ADMIN_PASSWORD_FILE")
	if endpoint == "" || passwordFile == "" {
		t.Skip("lab test: the A239 runner starts Elasticsearch and sets TRSTCTL_A239_ELASTICSEARCH_URL and TRSTCTL_A239_ELASTICSEARCH_ADMIN_PASSWORD_FILE")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl is required: %v", err)
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "elasticsearch-lab", Type: "elasticsearch", Endpoint: endpoint, AdminUser: "elastic",
		PasswordRef:  writeServedCredentialFile(t, "elasticsearch-lab-admin", strings.TrimSpace(string(adminPassword))),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on logs-*"},
		MaxTTL: "1h", AllowInsecureLoopback: true,
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
	registerServedTenant(t, h, "A239 Elasticsearch lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-elasticsearch-lab-1",
		map[string]any{"provider": "elasticsearch-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		ID        string    `json:"id"`
		Encoded   string    `json:"encoded"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Encoded == "" {
		t.Fatalf("credential: %v", err)
	}
	// Stock curl, authenticating with the leased API key.
	curl := func(method, path string) string {
		t.Helper()
		args := []string{"-sS", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, "-H", "Authorization: ApiKey " + credential.Encoded}
		if method == http.MethodPost {
			args = append(args, "-H", "Content-Type: application/json", "-d", `{"msg":"from the lease"}`)
		}
		out, err := exec.Command("curl", append(args, strings.TrimRight(endpoint, "/")+path)...).Output() // #nosec G204,G702 -- fixed tool, lab URL and the leased key (CWE-78)
		if err != nil {
			t.Fatalf("curl: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if code := curl(http.MethodGet, "/logs-lab/_search"); code != "200" {
		t.Fatalf("the leased key could not search logs-lab: HTTP %s", code)
	}
	if code := curl(http.MethodPost, "/logs-lab/_doc"); code != "403" {
		t.Fatalf("the leased key wrote to logs-lab: HTTP %s", code)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusOK {
		t.Fatalf("renew within the maximum lifetime: %d %s", status, body)
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
	if code := curl(http.MethodGet, "/logs-lab/_search"); code != "401" {
		t.Fatalf("Elasticsearch still accepts the invalidated key: HTTP %s", code)
	}
	t.Logf("A239_ELASTICSEARCH_OK lease=%s key=%s expires_at=%s", lease.ID, credential.ID, credential.ExpiresAt.Format(time.RFC3339))
}
