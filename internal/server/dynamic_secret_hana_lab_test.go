// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

// A239 against SAP HANA, express edition (2.00.088), configured by
// scripts/ci/a239-hana-lab.sh on an x86 runner (the image is x86 only):
// in tenant HXE, administrator LAB_ADMIN (USER ADMIN, SESSION ADMIN, CATALOG
// READ, ORDERS_READER WITH ADMIN OPTION; not SYSTEM), role ORDERS_READER
// (SELECT on schema ORDERS), and tables ORDERS.ITEMS and BILLING.INVOICES with
// one row each. A lease is a user the stock hdbsql reads ORDERS.ITEMS with and
// is refused an insert and BILLING.INVOICES; revoking the lease disconnects a
// session still open and drops the user, after which its login fails.
func TestServedDynamicHANAUserAgainstHANAExpressA239(t *testing.T) {
	dsnFile, container := os.Getenv("TRSTCTL_A239_HANA_ADMIN_DSN_FILE"), os.Getenv("TRSTCTL_A239_HANA_CONTAINER")
	if dsnFile == "" || container == "" {
		t.Skip("lab test: scripts/ci/a239-hana-lab.sh starts SAP HANA, express edition and sets TRSTCTL_A239_HANA_ADMIN_DSN_FILE and _CONTAINER")
	}
	raw, err := os.ReadFile(dsnFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := strings.TrimSpace(string(raw))
	hanaLabDirectRoundTrip(t, adminDSN)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "hana-lab", Type: "hana",
		AdminDSNRef:  writeServedCredentialFile(t, "hana-lab-admin-dsn", adminDSN),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "ORDERS_READER"}, MaxTTL: "1h",
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
	registerServedTenant(t, h, "A239 SAP HANA lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-hana-lab-1",
		map[string]any{"provider": "hana-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential userPassword
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.Password == "" {
		t.Fatalf("credential: %v", err)
	}
	// The stock hdbsql in the lab container, as the leased user.
	hdbsql := func(query string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, _ := exec.CommandContext(ctx, "docker", "exec", container, "/usr/sap/HXE/HDB90/exe/hdbsql", "-i", "90", "-d", "HXE", // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
			"-u", credential.Username, "-p", credential.Password, "-x", "-a", query).CombinedOutput()
		return string(out)
	}
	if out := hdbsql("SELECT ID FROM ORDERS.ITEMS"); !strings.Contains(out, "order-1") {
		t.Fatalf("the leased user did not read ORDERS.ITEMS:\n%s", out)
	}
	if out := hdbsql("INSERT INTO ORDERS.ITEMS VALUES ('from-the-lease')"); !strings.Contains(out, "insufficient privilege") {
		t.Fatalf("the database did not refuse the leased user's insert:\n%s", out)
	}
	if out := hdbsql("SELECT ID FROM BILLING.INVOICES"); !strings.Contains(out, "insufficient privilege") || strings.Contains(out, "invoice-1") {
		t.Fatalf("the database did not refuse the leased user BILLING.INVOICES:\n%s", out)
	}
	// A session the leased user keeps open across the revocation.
	target, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	target.User = url.UserPassword(credential.Username, credential.Password)
	db, err := sql.Open("hdb", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := t.Context()
	session, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("open the leased user's session: %v", err)
	}
	defer func() { _ = session.Close() }()
	var id string
	if err := session.QueryRowContext(ctx, "SELECT ID FROM ORDERS.ITEMS").Scan(&id); err != nil || id != "order-1" {
		t.Fatalf("the leased user's session did not read order-1: %q, %v", id, err)
	}

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusOK {
		t.Fatalf("renew within the maximum lifetime: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(120 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := session.QueryRowContext(ctx, "SELECT ID FROM ORDERS.ITEMS").Scan(&id); err == nil {
		t.Fatal("the session open across the revocation still reads ORDERS.ITEMS")
	}
	if out := hdbsql("SELECT ID FROM ORDERS.ITEMS"); !strings.Contains(out, "authentication failed") || strings.Contains(out, "order-1") {
		t.Fatalf("SAP HANA still accepts the revoked user's login:\n%s", out)
	}
	t.Logf("A239_HANA_OK lease=%s user=%s", lease.ID, credential.Username)
}

// hanaLabDirectRoundTrip creates and revokes one user through the provider
// itself before the served flow. The served path keeps a provider error in
// the outbox (the API answers 504 while issuance retries), and the provider's
// errors name SAP HANA's error code only, so this is where a lab failure
// reports which statement failed and why (CI 41578461348's first HANA run).
func hanaLabDirectRoundTrip(t *testing.T, adminDSN string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := dynsecret.OpenHANAExecutor(ctx, []byte(adminDSN))
	if err != nil {
		t.Fatalf("the administrator's connection: %v", err)
	}
	defer func() { _ = db.Close() }()
	backend, err := dynsecret.NewHANABackend(db, dynsecret.HANAConfig{AdminDSN: []byte(adminDSN), RoleBindings: map[string]string{"reader": "ORDERS_READER"}})
	if err != nil {
		t.Fatal(err)
	}
	ref, credential, err := backend.CreateCredential(ctx, dynsecret.GenerateRequest{Role: "reader", LeaseID: "a239-hana-direct-round-trip"})
	if err != nil {
		t.Fatalf("the provider, called directly: %v", err)
	}
	if err := backend.VerifyCredential(ctx, credential); err != nil {
		t.Fatalf("the provider's own check of its user: %v", err)
	}
	if err := backend.Revoke(ctx, ref); err != nil {
		t.Fatalf("the provider's revoke, called directly: %v", err)
	}
	if err := backend.VerifyCredential(ctx, credential); err == nil {
		t.Fatal("the directly revoked user still connects")
	}
}
