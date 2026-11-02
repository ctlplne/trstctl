// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A239 against stock RabbitMQ, configured by the A239 runner: the Debian
// rabbitmq-server lab image with the management plugin, administrator
// lab_admin, queue orders holding one message. A lease is a user the stock
// AMQP client (amqp-tools, in the same container) can consume orders with but
// not publish; revoking the lease deletes the user and RabbitMQ refuses its
// login.
func TestServedDynamicRabbitMQUserAgainstRabbitMQA239(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A239_RABBITMQ_URL")
	passwordFile := os.Getenv("TRSTCTL_A239_RABBITMQ_ADMIN_PASSWORD_FILE")
	container := os.Getenv("TRSTCTL_A239_RABBITMQ_CONTAINER")
	if endpoint == "" || passwordFile == "" || container == "" {
		t.Skip("lab test: the A239 runner starts RabbitMQ and sets TRSTCTL_A239_RABBITMQ_URL, _ADMIN_PASSWORD_FILE and _CONTAINER")
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "rabbitmq-lab", Type: "rabbitmq", Endpoint: endpoint, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "rabbitmq-lab-admin", strings.TrimSpace(string(adminPassword))),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on orders in /"},
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
	registerServedTenant(t, h, "A239 RabbitMQ lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-rabbitmq-lab-1",
		map[string]any{"provider": "rabbitmq-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
		VHost    string `json:"vhost"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" {
		t.Fatalf("credential: %v", err)
	}
	amqpURL := "amqp://" + credential.Username + ":" + credential.Password + "@localhost:5672/" + url.PathEscape(credential.VHost)
	// The stock AMQP client in the broker's container.
	amqp := func(args ...string) (string, error) {
		t.Helper()
		out, err := exec.Command("docker", append([]string{"exec", container, "timeout", "20"}, args...)...).CombinedOutput() // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		return strings.TrimSpace(string(out)), err
	}
	if out, err := amqp("amqp-consume", "-u", amqpURL, "-q", "orders", "-c", "1", "cat"); err != nil || out != "order-1" {
		t.Fatalf("the leased user consumed %q (%v), want order-1", out, err)
	}
	if out, err := amqp("amqp-publish", "-u", amqpURL, "-r", "orders", "-b", "from-the-lease"); err == nil || !strings.Contains(out, "ACCESS_REFUSED") {
		t.Fatalf("the leased user published: %v %s", err, out)
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
	if out, err := amqp("amqp-consume", "-u", amqpURL, "-q", "orders", "-c", "1", "cat"); err == nil || !strings.Contains(out, "ACCESS_REFUSED") {
		t.Fatalf("RabbitMQ still accepts the deleted user: %v %s", err, out)
	}
	t.Logf("A239_RABBITMQ_OK lease=%s user=%s vhost=%s", lease.ID, credential.Username, credential.VHost)
}
