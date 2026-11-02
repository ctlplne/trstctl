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

// A239 against stock Couchbase Server Community 8.0.2, configured by the A239
// runner: one node with the data, index and query services, administrator
// lab_admin, and buckets orders (document order-1) and payments, each with a
// primary index. A lease is a local user the stock query shell (cbq, in the
// same container) can read orders with but not payments; revoking the lease
// deletes the user and Couchbase refuses its login.
func TestServedDynamicCouchbaseUserAgainstCouchbaseA239(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A239_COUCHBASE_URL")
	passwordFile := os.Getenv("TRSTCTL_A239_COUCHBASE_ADMIN_PASSWORD_FILE")
	container := os.Getenv("TRSTCTL_A239_COUCHBASE_CONTAINER")
	if endpoint == "" || passwordFile == "" || container == "" {
		t.Skip("lab test: the A239 runner starts Couchbase and sets TRSTCTL_A239_COUCHBASE_URL, _ADMIN_PASSWORD_FILE and _CONTAINER")
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "couchbase-lab", Type: "couchbase", Endpoint: endpoint, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "couchbase-lab-admin", strings.TrimSpace(string(adminPassword))),
		AllowedRoles: []string{"orders"}, RoleBindings: map[string]string{"orders": "bucket_full_access on orders"},
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
	registerServedTenant(t, h, "A239 Couchbase lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-couchbase-lab-1",
		map[string]any{"provider": "couchbase-lab", "role": "orders", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" {
		t.Fatalf("credential: %v", err)
	}
	// The stock query shell in the server's container.
	cbq := func(statement string) string {
		t.Helper()
		out, _ := exec.Command("docker", "exec", container, "timeout", "60", "/opt/couchbase/bin/cbq", "-e", "couchbase://localhost", // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
			"-u", credential.Username, "-p", credential.Password, "-q", "-s", statement).CombinedOutput()
		return string(out)
	}
	if out := cbq("SELECT META().id FROM orders"); !strings.Contains(out, `"id": "order-1"`) {
		t.Fatalf("the leased user did not read orders:\n%s", out)
	}
	if out := cbq("SELECT META().id FROM payments"); !strings.Contains(out, "User does not have credentials to run SELECT queries on default:payments") {
		t.Fatalf("Couchbase did not refuse the leased user on payments:\n%s", out)
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
	if out := cbq("SELECT META().id FROM orders"); !strings.Contains(out, "401 Unauthorized") || strings.Contains(out, `"id": "order-1"`) {
		t.Fatalf("Couchbase still accepts the deleted user:\n%s", out)
	}
	t.Logf("A239_COUCHBASE_OK lease=%s user=%s", lease.ID, credential.Username)
}
