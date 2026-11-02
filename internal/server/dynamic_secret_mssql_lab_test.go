// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// mssqlLab is the SQL Server lab scripts/ci/a239-mssql-lab.sh builds on an
// x86 Linux runner: databases orders (table dbo.orders, row 1), payments, and
// orders_contained (partial containment, table dbo.orders, row 1), with
// contained database authentication on; admin DSN files for master and the
// contained database; and the container that holds the stock sqlcmd.
type mssqlLab struct {
	dsnFile, containedDSNFile, container string
}

func requireMSSQLLab(t *testing.T) mssqlLab {
	t.Helper()
	lab := mssqlLab{os.Getenv("TRSTCTL_A239_MSSQL_DSN_FILE"), os.Getenv("TRSTCTL_A239_MSSQL_CONTAINED_DSN_FILE"), os.Getenv("TRSTCTL_A239_MSSQL_CONTAINER")}
	if lab.dsnFile == "" || lab.containedDSNFile == "" || lab.container == "" {
		t.Skip("lab test: scripts/ci/a239-mssql-lab.sh starts SQL Server and sets TRSTCTL_A239_MSSQL_DSN_FILE, _CONTAINED_DSN_FILE and _CONTAINER")
	}
	return lab
}

// sqlcmd runs the stock sqlcmd in the lab container as the leased principal.
func (lab mssqlLab) sqlcmd(t *testing.T, ctx context.Context, user, password, database, query string) *exec.Cmd {
	t.Helper()
	return exec.CommandContext(ctx, "docker", "exec", lab.container, "/opt/mssql-tools18/bin/sqlcmd", "-S", "localhost", "-C", "-b", // #nosec G204,G702 -- fixed tool in the lab container (CWE-78)
		"-U", user, "-P", password, "-d", database, "-h", "-1", "-W", "-Q", query)
}

func (lab mssqlLab) run(t *testing.T, user, password, database, query string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, _ := lab.sqlcmd(t, ctx, user, password, database, query).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// leaseMSSQL issues a lease from a provider of providerType against the lab.
func leaseMSSQL(t *testing.T, providerType, dsnFile, database string) (*servedHarness, string, string, string, string) {
	t.Helper()
	dsn, err := os.ReadFile(dsnFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: providerType + "-lab", Type: providerType,
		AdminDSNRef: writeServedCredentialFile(t, providerType+"-lab-dsn", strings.TrimSpace(string(dsn))), Database: database,
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "db_datareader"}, MaxTTL: "1h",
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
	registerServedTenant(t, h, "A239 "+providerType+" lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-"+providerType+"-lab-1",
		map[string]any{"provider": providerType + "-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct{ Username, Password, Database string }
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.Database != database {
		t.Fatalf("credential: %v", err)
	}
	return h, tok, lease.ID, credential.Username, credential.Password
}

func renewAndRevokeMSSQL(t *testing.T, h *servedHarness, tok, leaseID string) {
	t.Helper()
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+leaseID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusOK {
		t.Fatalf("renew within the maximum lifetime: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+leaseID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(90 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+leaseID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// A239 against SQL Server 2022 (x86 Linux, CI): a lease is a login whose user
// in orders reads dbo.orders through db_datareader, is refused an insert and
// the payments database; revoking the lease ends a session it holds open and
// drops the user and login, after which sqlcmd's login fails.
func TestServedDynamicSQLServerLoginAgainstSQLServerA239(t *testing.T) {
	lab := requireMSSQLLab(t)
	h, tok, leaseID, user, password := leaseMSSQL(t, "mssql", lab.dsnFile, "orders")
	if out := lab.run(t, user, password, "orders", "SET NOCOUNT ON; SELECT id FROM dbo.orders"); out != "1" {
		t.Fatalf("the leased login did not read dbo.orders: %q", out)
	}
	if out := lab.run(t, user, password, "orders", "INSERT INTO dbo.orders (id) VALUES (2)"); !strings.Contains(out, "The INSERT permission was denied") {
		t.Fatalf("SQL Server did not refuse the leased login's insert: %q", out)
	}
	if out := lab.run(t, user, password, "payments", "SELECT 1"); !strings.Contains(out, "Login failed") && !strings.Contains(out, "Cannot open database") {
		t.Fatalf("SQL Server let the leased login into payments: %q", out)
	}
	// A session the leased login holds open across the revocation.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	held := lab.sqlcmd(t, ctx, user, password, "orders", "SELECT 'held-session-open'; WAITFOR DELAY '00:02:00'; SELECT 'held-session-finished'")
	reader, writer := io.Pipe()
	held.Stdout, held.Stderr = writer, writer
	if err := held.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 64)
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	done := make(chan error, 1)
	go func() { done <- held.Wait(); _ = writer.Close() }()
	var heldOutput []string
	for open := false; !open; {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the held session ended before revocation: %q", heldOutput)
			}
			heldOutput = append(heldOutput, line)
			open = strings.Contains(line, "held-session-open")
		case <-time.After(60 * time.Second):
			t.Fatalf("the held session did not start: %q", heldOutput)
		}
	}
	renewAndRevokeMSSQL(t, h, tok, leaseID)
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("the held session survived the revocation: %q", heldOutput)
	}
	for line := range lines {
		heldOutput = append(heldOutput, line)
	}
	if strings.Contains(strings.Join(heldOutput, "\n"), "held-session-finished") {
		t.Fatalf("the held session ran to completion after revocation: %q", heldOutput)
	}
	if out := lab.run(t, user, password, "orders", "SELECT 1"); !strings.Contains(out, "Login failed for user") {
		t.Fatalf("SQL Server still accepts the revoked login: %q", out)
	}
	t.Logf("A239_MSSQL_OK lease=%s login=%s held_session=%q", leaseID, user, heldOutput[len(heldOutput)-1])
}

// A239 Azure SQL contained users, against SQL Server's contained database
// users (the same T-SQL Azure SQL Database runs): a lease is a user in
// orders_contained that logs in to that database alone, reads through
// db_datareader and is refused an insert; after revocation its login fails.
func TestServedDynamicAzureSQLContainedUserAgainstSQLServerA239(t *testing.T) {
	lab := requireMSSQLLab(t)
	h, tok, leaseID, user, password := leaseMSSQL(t, "azure-sql", lab.containedDSNFile, "orders_contained")
	if out := lab.run(t, user, password, "orders_contained", "SET NOCOUNT ON; SELECT id FROM dbo.orders"); out != "1" {
		t.Fatalf("the contained user did not read dbo.orders: %q", out)
	}
	if out := lab.run(t, user, password, "orders_contained", "INSERT INTO dbo.orders (id) VALUES (2)"); !strings.Contains(out, "The INSERT permission was denied") {
		t.Fatalf("SQL Server did not refuse the contained user's insert: %q", out)
	}
	if out := lab.run(t, user, password, "orders", "SELECT 1"); !strings.Contains(out, "Login failed") {
		t.Fatalf("the contained user logged in to another database: %q", out)
	}
	renewAndRevokeMSSQL(t, h, tok, leaseID)
	if out := lab.run(t, user, password, "orders_contained", "SELECT 1"); !strings.Contains(out, "Login failed for user") {
		t.Fatalf("SQL Server still accepts the dropped contained user: %q", out)
	}
	t.Logf("A239_AZURE_SQL_OK lease=%s user=%s", leaseID, user)
}
