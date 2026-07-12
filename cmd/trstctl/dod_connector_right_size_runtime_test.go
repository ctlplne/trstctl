//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const dodRightSizeTenant = "d0d00000-0000-4000-8000-000000000401"

// TestDODConnectorRightSizeProductionAssembly proves the shipped cmd/trstctl
// executable attaches remediation through its signed-license attachEE seam. The
// proof bootstraps a tenant through the shipped CLI, starts the real control
// plane plus its separate signer child, and drives only served HTTP routes. No
// test-owned registry, Deps, handler, or edition attachment exists on this path.
func TestDODConnectorRightSizeProductionAssembly(t *testing.T) {
	external := proof.StartCommand(t, "connector_right_size.dispatch")
	root := t.TempDir()
	licenseFile, trustedPublicKey := dodRightSizeLicense(t, root)
	control := proof.BuildShippedProcess(t, "connector_right_size.dispatch", trustedPublicKey)

	// Production accepts plaintext entitlement APIs only on loopback. The gate's
	// parent-owned emulator lives outside the Linux runtime-runner, so this bridge
	// changes only the network namespace: every request and response still reaches
	// the independently launched, receipt-producing substrate.
	connectorEndpoint := dodRightSizeLoopbackBridge(t, external.Endpoint())

	postgresPort := dodFreePort(t)
	st, closeStore, err := server.DODOpenBundledStore(context.Background(), filepath.Join(root, "postgres"), postgresPort)
	if err != nil {
		t.Fatal(err)
	}
	_ = st
	t.Cleanup(closeStore)

	serverPort := dodFreePort(t)
	cfg := config.Default()
	cfg.Server.Addr = "127.0.0.1:" + strconv.Itoa(serverPort)
	cfg.Server.TLS.Mode = config.TLSDisabled
	cfg.Server.TLS.AllowPlaintextDev = true
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", postgresPort)
	cfg.NATS.Mode = config.NATSEmbedded
	cfg.NATS.StoreDir = filepath.Join(root, "nats")
	cfg.License.File = licenseFile
	cfg.Migrate.Auto = true
	cfg.RateLimit.Enabled = false
	cfg.Telemetry.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(root, "secrets-kek.bin")
	// The signer hardens its socket directory. A file directly under /tmp would
	// make it try to chmod the shared sticky directory, which correctly fails for
	// the non-root shipped runtime. Give it one short, private directory it owns;
	// using /tmp explicitly also keeps the UDS path below the platform length cap.
	signerRuntimeDir, err := os.MkdirTemp("/tmp", "trstctl-right-size-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(signerRuntimeDir) })
	cfg.Signer.Socket = filepath.Join(signerRuntimeDir, "signer.sock")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "signer-auth.bin")
	cfg.Signer.AllowInsecureDevNonLinux = true
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.pem")
	cfg.Connectors.AllowPrivateCIDRs = []string{"127.0.0.0/8"}
	cfg.Connectors.AllowInsecureHTTP = true
	cfg.Connectors.RightSize = []config.ConnectorRightSizeBinding{{
		TenantID: dodRightSizeTenant, Connector: "least-privilege",
		Endpoint: connectorEndpoint, TokenRef: "secret://right-size/token",
	}}
	configFile := dodRightSizeWriteConfig(t, root, cfg)
	env := dodRightSizeProcessEnv(configFile)
	token := dodRightSizeBootstrapToken(t, control, root, env)

	control.Start(root, env)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(serverPort)
	client := &http.Client{Timeout: 10 * time.Second}
	dodRightSizeWaitHealthy(t, client, baseURL, control)

	dodRightSizeAPIRequest(t, client, baseURL, token, http.MethodPost, "/api/v1/secrets/store", "dod-right-size-secret", map[string]any{
		"name": "right-size/token", "value": "right-size-token",
	}, http.StatusCreated)
	ownerBody := dodRightSizeAPIRequest(t, client, baseURL, token, http.MethodPost, "/api/v1/owners", "dod-right-size-owner", map[string]any{
		"kind": "workload", "name": "right-size proof owner",
	}, http.StatusCreated)
	var owner struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(ownerBody, &owner) != nil || owner.ID == "" {
		t.Fatalf("decode right-size owner: %s", ownerBody)
	}
	identityBody := dodRightSizeAPIRequest(t, client, baseURL, token, http.MethodPost, "/api/v1/identities", "dod-right-size-identity", map[string]any{
		"kind": "service_account", "name": "right-size-service-1", "owner_id": owner.ID,
		"attributes": map[string]any{
			"granted_scopes": []string{"read", "write"}, "used_scopes": []string{"read"},
			"last_used_at": "2026-07-10T12:00:00Z",
		},
	}, http.StatusCreated)
	var identity struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(identityBody, &identity) != nil || identity.ID == "" {
		t.Fatalf("decode right-size identity: %s", identityBody)
	}
	runCommand := map[string]any{
		"target_identity_id": identity.ID, "reason": "remove unused write scope",
		"connector": "least-privilege", "target": "service-1",
		"remove_scopes": []string{"write"}, "recommended_scopes": []string{"read"},
	}
	runBody := dodRightSizeAPIRequest(t, client, baseURL, token, http.MethodPost, "/api/v1/remediation/playbooks/nhi-right-size/runs", "dod-right-size-api-1", runCommand, http.StatusCreated)
	if !bytes.Contains(runBody, []byte(`"phase":"right_size_connector_intent_queued"`)) {
		t.Fatalf("served right-size route did not queue the production intent: %s", runBody)
	}
	replayedRunBody := dodRightSizeAPIRequest(t, client, baseURL, token, http.MethodPost, "/api/v1/remediation/playbooks/nhi-right-size/runs", "dod-right-size-api-1", runCommand, http.StatusCreated)
	if !bytes.Equal(runBody, replayedRunBody) {
		t.Fatalf("served idempotency replay changed the right-size result: first=%s replay=%s", runBody, replayedRunBody)
	}

	readback := dodRightSizeWaitReadback(t, client, external.Endpoint())
	// The receiver mutates before the production worker performs its authenticated
	// readback and projects the terminal receipt. Wait on the shipped read model as
	// well, so observing the external mutation cannot race the user-visible proof.
	dodRightSizeWaitDelivery(t, client, baseURL, token)
	deliveryRequest, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/connectors/deliveries", nil)
	if err != nil {
		t.Fatal(err)
	}
	deliveryRequest.Header.Set("Authorization", "Bearer "+token)
	deliveryResponse := control.Do(deliveryRequest)
	session := proof.StartResponse(t, "connector_right_size.dispatch", deliveryResponse)
	if !bytes.Contains(session.ResponseBody(), []byte(`"status":"delivered"`)) || !bytes.Contains(session.ResponseBody(), []byte(`"reason":"entitlements_mutated"`)) {
		t.Fatalf("right-size delivery receipt is not user-visible evidence: %s", session.ResponseBody())
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{
		Destination: []byte(external.Endpoint() + "/v1/entitlements/service-1"),
		Written:     []byte(`{"scopes":["read"]}`), ReadBack: readback, ExecutionReceipt: executionReceipt,
	}))
}

func dodRightSizeLicense(t *testing.T, root string) (string, []byte) {
	t.Helper()
	privateKey, publicKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "dod-right-size-license", Customer: "DoD runtime", Tier: license.TierEnterprise,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "enterprise-license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, publicKey
}

func dodRightSizeLoopbackBridge(t *testing.T, upstream string) string {
	t.Helper()
	target, err := dodRightSizeBridgeTarget(upstream)
	if err != nil {
		t.Fatalf("invalid parent-owned right-size endpoint %q", upstream)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := &http.Server{
		Handler:           httputil.NewSingleHostReverseProxy(target),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	go func() { _ = bridge.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = bridge.Shutdown(ctx)
	})
	return "http://" + listener.Addr().String()
}

func dodRightSizeBridgeTarget(upstream string) (*url.URL, error) {
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Opaque != "" ||
		target.Path != "" || target.RawPath != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, fmt.Errorf("right-size bridge requires an HTTP origin")
	}
	host := target.Hostname()
	if host != "127.0.0.1" && host != "host.docker.internal" {
		return nil, fmt.Errorf("right-size bridge host %q is not gate-owned loopback", host)
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 || target.Host != net.JoinHostPort(host, strconv.Itoa(port)) {
		return nil, fmt.Errorf("right-size bridge requires one canonical explicit port")
	}
	return target, nil
}

func TestDODConnectorRightSizeBridgeTargetIsClosed(t *testing.T) {
	for _, valid := range []string{"http://127.0.0.1:18080", "http://host.docker.internal:18080"} {
		if _, err := dodRightSizeBridgeTarget(valid); err != nil {
			t.Errorf("valid bridge target %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"https://127.0.0.1:18080", "http://localhost:18080", "http://example.com:18080",
		"http://user@127.0.0.1:18080", "http://127.0.0.1", "http://127.0.0.1:0",
		"http://127.0.0.1:18080/", "http://127.0.0.1:18080?x=1", "http://127.0.0.1:18080#x",
	} {
		if _, err := dodRightSizeBridgeTarget(invalid); err == nil {
			t.Errorf("unsafe bridge target %q passed", invalid)
		}
	}
}

func dodFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func dodRightSizeWriteConfig(t *testing.T, root string, cfg *config.Config) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dodRightSizeProcessEnv(configFile string) []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TRSTCTL_") {
			env = append(env, value)
		}
	}
	return append(env, "TRSTCTL_CONFIG_FILE="+configFile)
}

func dodRightSizeBootstrapToken(t *testing.T, control *proof.ShippedProcess, directory string, env []string) string {
	t.Helper()
	scopes := strings.Join([]string{
		"owners:read", "owners:write", "identities:read", "identities:write",
		"nhi:read", "incidents:read", "incidents:write", "connectors:read",
		"secrets:read", "secrets:write",
	}, ",")
	token := control.CreateToken(directory, env, "token", "create", "--tenant", dodRightSizeTenant, "--tenant-name", "DoD right size", "--subject", "dod-right-size-operator", "--scopes", scopes)
	if token == "" {
		t.Fatal("bootstrap returned an empty right-size API token")
	}
	return token
}

func dodRightSizeWaitHealthy(t *testing.T, client *http.Client, baseURL string, control *proof.ShippedProcess) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(baseURL + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode/100 == 2 {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("shipped right-size control plane did not become healthy: %s", control.Logs())
}

func dodRightSizeAPIRequest(t *testing.T, client *http.Client, baseURL, token, method, path, idempotencyKey string, value any, want int) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s = %d, want %d; body=%s", method, path, response.StatusCode, want, body)
	}
	return body
}

func dodRightSizeWaitReadback(t *testing.T, client *http.Client, endpoint string) []byte {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(endpoint + "/dod/readback")
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && bytes.Equal(body, []byte(`{"scopes":["read"]}`)) {
				return body
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("production outbox did not right-size the external entitlement before the deadline")
	return nil
}

func dodRightSizeWaitDelivery(t *testing.T, client *http.Client, baseURL, token string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/connectors/deliveries?limit=20", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK &&
				bytes.Contains(body, []byte(`"status":"delivered"`)) &&
				bytes.Contains(body, []byte(`"reason":"entitlements_mutated"`)) {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("production right-size delivery did not reach its user-visible terminal state before the deadline")
}
