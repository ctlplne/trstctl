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

// A239 against stock Apache Cassandra, configured by the A239 runner: one node
// with PasswordAuthenticator and CassandraAuthorizer, administrator lab_admin
// (CREATE, ALTER, DROP, DESCRIBE and AUTHORIZE on ALL ROLES, not a
// superuser), role orders_reader (SELECT on keyspace orders), and tables
// orders.items and billing.invoices holding one row each. A lease is a login
// role the stock cqlsh reads orders.items with, and is refused an insert and
// the billing keyspace; revoking the lease drops the role, which refuses a
// cqlsh session still connected on its next query and a new login.
func TestServedDynamicCassandraRoleAgainstCassandraA239(t *testing.T) {
	addr := os.Getenv("TRSTCTL_A239_CASSANDRA_ADDR")
	passwordFile := os.Getenv("TRSTCTL_A239_CASSANDRA_ADMIN_PASSWORD_FILE")
	container := os.Getenv("TRSTCTL_A239_CASSANDRA_CONTAINER")
	if addr == "" || passwordFile == "" || container == "" {
		t.Skip("lab test: the A239 runner starts Cassandra and sets TRSTCTL_A239_CASSANDRA_ADDR, _ADMIN_PASSWORD_FILE and _CONTAINER")
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "cassandra-lab", Type: "cassandra", Addr: addr, AllowPlaintext: true, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "cassandra-lab-admin", strings.TrimSpace(string(adminPassword))),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "orders_reader"},
		MaxTTL: "1h",
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
	registerServedTenant(t, h, "A239 Cassandra lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-cassandra-lab-1",
		map[string]any{"provider": "cassandra-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.Password == "" {
		t.Fatalf("credential: %v", err)
	}
	// The stock cqlsh in the node's container, with the lease's credential in
	// a credentials file rather than on its command line.
	credentials := "/tmp/" + lease.ID + ".credentials"
	write := exec.Command("docker", "exec", "-i", container, "sh", "-c", "umask 077 && cat > "+credentials) // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
	write.Stdin = strings.NewReader("[plain_text_auth]\nusername = " + credential.Username + "\npassword = " + credential.Password + "\n")
	if out, err := write.CombinedOutput(); err != nil {
		t.Fatalf("credentials file: %v %s", err, out)
	}
	cqlsh := func(statement string) string {
		t.Helper()
		cmd := exec.Command("docker", "exec", container, "timeout", "90", "cqlsh", "--credentials", credentials, "-e", statement) // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if out := cqlsh("SELECT id FROM orders.items"); !strings.Contains(out, "order-1") {
		t.Fatalf("the leased role did not read orders.items:\n%s", out)
	}
	if out := cqlsh("INSERT INTO orders.items (id) VALUES ('from-the-lease')"); !strings.Contains(out, "Unauthorized") {
		t.Fatalf("the node did not refuse the leased role's insert:\n%s", out)
	}
	if out := cqlsh("SELECT id FROM billing.invoices"); !strings.Contains(out, "Unauthorized") || strings.Contains(out, "invoice-1") {
		t.Fatalf("the node did not refuse the leased role another keyspace:\n%s", out)
	}

	// A stock cqlsh that stays connected as the leased role, to show that the
	// drop refuses its next query on the open connection.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	live := exec.CommandContext(ctx, "docker", "exec", "-i", "-e", "PYTHONUNBUFFERED=1", container, "timeout", "200", // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		"cqlsh", "--credentials", credentials)
	stdin, err := live.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	live.Stdout, live.Stderr = writer, writer
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	lines := make(chan string, 256)
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	go func() { _ = live.Wait(); _ = writer.Close() }()
	var liveOutput []string
	await := func(match func(string) bool, within time.Duration) bool {
		t.Helper()
		timer := time.NewTimer(within)
		defer timer.Stop()
		for {
			select {
			case line, open := <-lines:
				if !open {
					return false
				}
				liveOutput = append(liveOutput, line)
				if match(line) {
					return true
				}
			case <-timer.C:
				return false
			}
		}
	}
	query := func() {
		t.Helper()
		if _, err := io.WriteString(stdin, "SELECT id FROM orders.items;\n"); err != nil {
			t.Fatalf("the live session ended: %v\n%s", err, strings.Join(liveOutput, "\n"))
		}
	}
	query()
	if !await(func(line string) bool { return strings.Contains(line, "order-1") }, 90*time.Second) {
		t.Fatalf("the live session did not read order-1:\n%s", strings.Join(liveOutput, "\n"))
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
	revokedAt := time.Now()
	var refusal string
	refused := false
	for deadline := revokedAt.Add(30 * time.Second); !refused && time.Now().Before(deadline); {
		query()
		refused = await(func(line string) bool { refusal = line; return strings.Contains(line, "Unauthorized") }, 2*time.Second)
	}
	if !refused {
		t.Fatalf("the live session was not refused after revocation:\n%s", strings.Join(liveOutput, "\n"))
	}
	refusedAfter := time.Since(revokedAt).Round(100 * time.Millisecond)
	if out := cqlsh("SELECT id FROM orders.items"); !strings.Contains(out, "Bad credentials") || strings.Contains(out, "order-1") {
		t.Fatalf("Cassandra still accepts the revoked role's login:\n%s", out)
	}
	_ = exec.Command("docker", "exec", container, "rm", "-f", credentials).Run() // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
	t.Logf("A239_CASSANDRA_OK lease=%s role=%s open_connection_refused_after=%s refusal=%q", lease.ID, credential.Username, refusedAfter, refusal)
}
