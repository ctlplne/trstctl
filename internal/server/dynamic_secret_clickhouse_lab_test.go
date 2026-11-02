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

// A239 against stock ClickHouse, configured by the A239 runner: database lab
// with table orders, role orders_reader granted SELECT on lab.*, administrator
// lab_admin. A lease is a user that stock curl can read lab.orders with but not
// write to; revoking the lease drops the user and ClickHouse refuses the login.
func TestServedDynamicClickHouseLeaseAgainstClickHouseA239(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A239_CLICKHOUSE_URL")
	passwordFile := os.Getenv("TRSTCTL_A239_CLICKHOUSE_ADMIN_PASSWORD_FILE")
	if endpoint == "" || passwordFile == "" {
		t.Skip("lab test: the A239 runner starts ClickHouse and sets TRSTCTL_A239_CLICKHOUSE_URL and TRSTCTL_A239_CLICKHOUSE_ADMIN_PASSWORD_FILE")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl is required: %v", err)
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "clickhouse-lab", Type: "clickhouse", Endpoint: endpoint, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "clickhouse-lab-admin", strings.TrimSpace(string(adminPassword))),
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
	registerServedTenant(t, h, "A239 ClickHouse lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-clickhouse-lab-1",
		map[string]any{"provider": "clickhouse-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		ValidUntil string `json:"valid_until"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" {
		t.Fatalf("credential: %v", err)
	}
	// Stock curl against the HTTP interface, as the leased user.
	curl := func(statement string) (string, string) {
		t.Helper()
		out, err := exec.Command("curl", "-sS", "-w", "\n%{http_code}", "-u", credential.Username+":"+credential.Password, // #nosec G204,G702 -- fixed tool, lab URL and the leased credential (CWE-78)
			"--data-binary", statement, endpoint).Output()
		if err != nil {
			t.Fatalf("curl: %v", err)
		}
		text := strings.TrimSpace(string(out))
		i := strings.LastIndex(text, "\n")
		if i < 0 {
			return "", text
		}
		return strings.TrimSpace(text[:i]), text[i+1:]
	}
	if rows, code := curl("SELECT count() FROM lab.orders"); code != "200" || rows != "2" {
		t.Fatalf("the leased user read %q (HTTP %s), want 2 rows", rows, code)
	}
	if _, code := curl("INSERT INTO lab.orders VALUES (3)"); code == "200" {
		t.Fatal("the leased user could write")
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
	if _, code := curl("SELECT 1"); code == "200" {
		t.Fatal("ClickHouse still accepts the dropped user")
	}
	t.Logf("A239_CLICKHOUSE_OK lease=%s user=%s valid_until=%s", lease.ID, credential.Username, credential.ValidUntil)
}
