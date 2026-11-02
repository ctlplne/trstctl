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

// A239 against stock Apache Kafka, configured by the A239 runner: one KRaft
// node with a SASL_PLAINTEXT (SCRAM-SHA-512) listener on a loopback port, the
// StandardAuthorizer, administrator lab_admin, and topic orders holding one
// message. A lease is a SCRAM user the stock console consumer can read orders
// with (in consumer group orders-app) but whose produce the broker refuses;
// revoking the lease deletes its ACLs, which refuse a stock consumer still
// connected on its next request, and its credential, after which the stock
// client's login fails.
func TestServedDynamicKafkaUserAgainstKafkaA239(t *testing.T) {
	addr := os.Getenv("TRSTCTL_A239_KAFKA_ADDR")
	passwordFile := os.Getenv("TRSTCTL_A239_KAFKA_ADMIN_PASSWORD_FILE")
	container := os.Getenv("TRSTCTL_A239_KAFKA_CONTAINER")
	if addr == "" || passwordFile == "" || container == "" {
		t.Skip("lab test: the A239 runner starts Kafka and sets TRSTCTL_A239_KAFKA_ADDR, _ADMIN_PASSWORD_FILE and _CONTAINER")
	}
	adminPassword, err := os.ReadFile(passwordFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "kafka-lab", Type: "kafka", Addr: addr, AllowPlaintext: true, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "kafka-lab-admin", strings.TrimSpace(string(adminPassword))),
		AllowedRoles: []string{"consumer"}, RoleBindings: map[string]string{"consumer": "read,describe on topic:orders; read on group:orders-app"},
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
	registerServedTenant(t, h, "A239 Kafka lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-kafka-lab-1",
		map[string]any{"provider": "kafka-lab", "role": "consumer", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct{ Username, Password, Mechanism string }
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.Mechanism != "SCRAM-SHA-512" {
		t.Fatalf("credential: %v", err)
	}
	// The stock console clients in the broker's container, with the lease's
	// SCRAM credential in a client properties file.
	properties := "/tmp/" + lease.ID + ".properties"
	write := exec.Command("docker", "exec", "-i", container, "sh", "-c", "umask 077 && cat > "+properties) // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
	write.Stdin = strings.NewReader("security.protocol=SASL_PLAINTEXT\nsasl.mechanism=SCRAM-SHA-512\n" +
		"sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username=\"" + credential.Username + "\" password=\"" + credential.Password + "\";\n")
	if out, err := write.CombinedOutput(); err != nil {
		t.Fatalf("client properties: %v %s", err, out)
	}
	kafka := func(stdin string, args ...string) string {
		t.Helper()
		cmd := exec.Command("docker", append([]string{"exec", "-i", container, "timeout", "90"}, args...)...) // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		cmd.Stdin = strings.NewReader(stdin)
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	consume := func() string {
		return kafka("", "/opt/kafka/bin/kafka-console-consumer.sh", "--bootstrap-server", addr, "--topic", "orders", "--group", "orders-app",
			"--from-beginning", "--max-messages", "1", "--timeout-ms", "30000", "--consumer.config", properties)
	}
	if out := consume(); !strings.Contains(out, "order-1") {
		t.Fatalf("the leased user did not consume order-1:\n%s", out)
	}
	// Without idempotence, so the refusal is the topic's (an idempotent
	// producer is refused earlier, at the cluster, for the same missing WRITE).
	if out := kafka("from-the-lease\n", "/opt/kafka/bin/kafka-console-producer.sh", "--bootstrap-server", addr, "--topic", "orders",
		"--producer.config", properties, "--producer-property", "enable.idempotence=false"); !strings.Contains(out, "TopicAuthorizationException: Not authorized to access topics: [orders]") {
		t.Fatalf("the broker did not refuse the leased user's produce:\n%s", out)
	}
	// A stock consumer that stays connected as the leased user, to show that
	// the ACLs' deletion refuses its next request on the open connection: the
	// broker authorizes every request and does not log the user in again.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	live := exec.CommandContext(ctx, "docker", "exec", container, "timeout", "150", "/opt/kafka/bin/kafka-console-consumer.sh", // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		"--bootstrap-server", addr, "--topic", "orders", "--group", "orders-app", "--consumer.config", properties)
	reader, writer := io.Pipe()
	live.Stdout, live.Stderr = writer, writer
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
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
	_ = kafka("order-2\n", "/opt/kafka/bin/kafka-console-producer.sh", "--bootstrap-server", "localhost:19092", "--topic", "orders")
	if !await(func(line string) bool { return line == "order-2" }, 90*time.Second) {
		t.Fatalf("the live consumer did not read order-2:\n%s", strings.Join(liveOutput, "\n"))
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
	var refusal string
	if !await(func(line string) bool { refusal = line; return strings.Contains(line, "AuthorizationException") }, 90*time.Second) {
		t.Fatalf("the live consumer was not refused after revocation:\n%s", strings.Join(liveOutput, "\n"))
	}
	for _, line := range liveOutput {
		if strings.Contains(line, "Authentication failed") {
			t.Fatalf("the live consumer logged in again instead of being refused on its open connection:\n%s", strings.Join(liveOutput, "\n"))
		}
	}
	if out := consume(); !strings.Contains(out, "Authentication failed") || strings.Contains(out, "order-1") {
		t.Fatalf("Kafka still accepts the revoked user's login:\n%s", out)
	}
	_ = kafka("", "rm", "-f", properties)
	t.Logf("A239_KAFKA_OK lease=%s user=%s open_connection_refusal=%q", lease.ID, credential.Username, refusal)
}
