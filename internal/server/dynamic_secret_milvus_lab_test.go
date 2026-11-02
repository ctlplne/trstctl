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

// A239 against stock Milvus 2.6.26 standalone, configured by the A239 runner:
// authorization on, root's password set at bootstrap, collections orders
// (entity 1) and payments (entity 7), and role orders_reader holding
// CollectionReadOnly on orders. A lease is a user stock curl (in the same
// container) can query orders with, but not payments, and cannot insert with;
// revoking the lease drops the user and Milvus refuses its next request.
func TestServedDynamicMilvusUserAgainstMilvusA239(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A239_MILVUS_URL")
	passwordFile := os.Getenv("TRSTCTL_A239_MILVUS_ADMIN_PASSWORD_FILE")
	container := os.Getenv("TRSTCTL_A239_MILVUS_CONTAINER")
	if endpoint == "" || passwordFile == "" || container == "" {
		t.Skip("lab test: the A239 runner starts Milvus and sets TRSTCTL_A239_MILVUS_URL, _ADMIN_PASSWORD_FILE and _CONTAINER")
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "milvus-lab", Type: "milvus", Endpoint: endpoint, AdminUser: "root",
		PasswordRef:  writeServedCredentialFile(t, "milvus-lab-root", strings.TrimSpace(string(adminPassword))),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "orders_reader"},
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
	registerServedTenant(t, h, "A239 Milvus lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-milvus-lab-1",
		map[string]any{"provider": "milvus-lab", "role": "reader", "ttl_seconds": 600})
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
	// Stock curl in the Milvus container, against the RESTful API.
	curl := func(path, payload string) string {
		t.Helper()
		out, _ := exec.Command("docker", "exec", container, "curl", "-sS", "-m", "30", "-X", "POST", "http://localhost:19530"+path, // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
			"-H", "Authorization: Bearer "+credential.Username+":"+credential.Password, "-H", "Content-Type: application/json", "-d", payload).CombinedOutput()
		return string(out)
	}
	query := func(collection string) string {
		return curl("/v2/vectordb/entities/query", `{"collectionName":"`+collection+`","filter":"id >= 0","outputFields":["id"]}`)
	}
	if out := query("orders"); !strings.Contains(out, `"code":0`) || !strings.Contains(out, `{"id":1}`) {
		t.Fatalf("the leased user did not query orders: %s", out)
	}
	if out := query("payments"); !strings.Contains(out, "PermissionDenied") {
		t.Fatalf("Milvus did not refuse the leased user on payments: %s", out)
	}
	if out := curl("/v2/vectordb/entities/insert", `{"collectionName":"orders","data":[{"id":2,"vector":[0.5,0.6]}]}`); !strings.Contains(out, "PermissionDenied") {
		t.Fatalf("Milvus did not refuse the leased user's insert: %s", out)
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
	if out := query("orders"); !strings.Contains(out, `"code":1800`) || strings.Contains(out, `{"id":1}`) {
		t.Fatalf("Milvus still accepts the dropped user: %s", out)
	}
	t.Logf("A239_MILVUS_OK lease=%s user=%s", lease.ID, credential.Username)
}
