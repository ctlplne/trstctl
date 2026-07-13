//go:build trstctl_dodproof

// SPDX-License-Identifier: LicenseRef-trstctl-EE

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodPQCTenant = "d0d00000-0000-4000-8000-000000000501"
)

// TestDODPQCProductionAssembly launches the exact full cmd/trstctl artifact for
// each PQC census row. No test constructs Deps, a connector registry, protocol
// server, licensed signer, SPIFFE issuer, or migration service.
func TestDODPQCProductionAssembly(t *testing.T) {
	only := dodPQCSelection(t,
		"pqc_end_to_end.pure_mldsa_leaf_stock_clients",
		"pqc_end_to_end.multikey_spiffe_hybrid_svid",
		"pqc_end_to_end.automated_rollout_tls_findings",
	)
	if only == "" || only == "pqc_end_to_end.pure_mldsa_leaf_stock_clients" {
		t.Run("pure_mldsa_leaf_stock_clients", func(t *testing.T) {
			dodRunPureMLDSAProof(t)
		})
	}
	if only == "" || only == "pqc_end_to_end.multikey_spiffe_hybrid_svid" {
		t.Run("multikey_spiffe_hybrid_svid", func(t *testing.T) {
			dodRunMultiKeySPIFFEProof(t)
		})
	}
	if only == "" || only == "pqc_end_to_end.automated_rollout_tls_findings" {
		t.Run("automated_rollout_tls_findings", func(t *testing.T) {
			dodRunAutomatedTLSRolloutProof(t)
		})
	}
}

func dodPQCSelection(t *testing.T, allowed ...string) string {
	t.Helper()
	only := proof.OnlyExpectation(t)
	if only == "" {
		return ""
	}
	for _, id := range allowed {
		if only == id {
			return only
		}
	}
	t.Fatalf("DOD-CENSUS: PQC runtime received unrelated expectation %q", only)
	return ""
}

type dodPQCRuntime struct {
	baseURL string
	token   string
	caFile  string
	client  *http.Client
	cfg     *config.Config
}

func dodStartPQCRuntime(t *testing.T, id string, configure func(*config.Config, string, *proof.ExternalSubstrate)) (*dodPQCRuntime, *proof.ShippedProcess, *proof.ExternalSubstrate) {
	t.Helper()
	external := proof.StartCommand(t, id)
	root := t.TempDir()
	licenseFile, trustedPublicKey := dodRightSizeLicense(t, root)
	control := proof.BuildShippedProcess(t, id, trustedPublicKey)
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
	signerRuntimeDir, err := os.MkdirTemp("/tmp", "trstctl-pqc-dod-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(signerRuntimeDir) })
	cfg.Signer.Socket = filepath.Join(signerRuntimeDir, "signer.sock")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "signer-auth.bin")
	cfg.Signer.AllowInsecureDevNonLinux = true
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.pem")
	if configure != nil {
		configure(cfg, root, external)
	}
	configFile := dodRightSizeWriteConfig(t, root, cfg)
	env := dodRightSizeProcessEnv(configFile)
	token := dodPQCBootstrapToken(t, control, root, env)
	control.Start(root, env)
	t.Cleanup(control.Stop)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(serverPort)
	client := &http.Client{Timeout: 15 * time.Second}
	dodRightSizeWaitHealthy(t, client, baseURL, control)
	return &dodPQCRuntime{
		baseURL: baseURL, token: token, caFile: cfg.CA.CertFile,
		client: client, cfg: cfg,
	}, control, external
}

func dodPQCBootstrapToken(t *testing.T, control *proof.ShippedProcess, directory string, env []string) string {
	t.Helper()
	scopes := strings.Join([]string{
		"certs:read", "certs:request", "certs:issue", "issuers:read",
		"connectors:read", "connectors:write", "discovery:read", "discovery:write", "risk:read",
	}, ",")
	token := control.CreateToken(directory, env, "token", "create", "--tenant", dodPQCTenant,
		"--tenant-name", "DoD PQC", "--subject", "dod-pqc-operator", "--scopes", scopes)
	if token == "" {
		t.Fatal("bootstrap returned an empty PQC API token")
	}
	return token
}

func dodRunPureMLDSAProof(t *testing.T) {
	runtime, control, external := dodStartPQCRuntime(t, "pqc_end_to_end.pure_mldsa_leaf_stock_clients", func(cfg *config.Config, _ string, _ *proof.ExternalSubstrate) {
		cfg.Protocols.EST = config.ProtocolToggle{Enabled: true, TenantID: dodPQCTenant}
	})
	csrResponse := dodPQCExternalJSON(t, runtime.client, external.Endpoint(), http.MethodGet, "/dod/csr", nil)
	var csr struct {
		DER []byte `json:"csr_der_b64"`
	}
	if err := json.Unmarshal(csrResponse, &csr); err != nil || len(csr.DER) == 0 {
		t.Fatalf("decode stock OpenSSL ML-DSA CSR: %v body=%s", err, csrResponse)
	}
	requestBody := []byte(base64.StdEncoding.EncodeToString(csr.DER))
	request, err := http.NewRequest(http.MethodPost, runtime.baseURL+"/.well-known/est/simpleenroll", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/pkcs10")
	request.Header.Set("Authorization", "Bearer "+runtime.token)
	session := proof.StartResponse(t, "pqc_end_to_end.pure_mldsa_leaf_stock_clients", control.Do(request))
	if session.StatusCode() != http.StatusOK {
		t.Fatalf("pure ML-DSA EST status=%d body=%s", session.StatusCode(), session.ResponseBody())
	}
	pkcs7DER, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(session.ResponseBody())))
	if err != nil || len(pkcs7DER) == 0 {
		t.Fatalf("decode EST PKCS7: %v", err)
	}
	caPEM, err := os.ReadFile(runtime.caFile)
	if err != nil {
		t.Fatal(err)
	}
	report := dodPQCExternalJSON(t, runtime.client, external.Endpoint(), http.MethodPost, "/dod/verify", map[string]any{
		"mode": "pure_mldsa_leaf", "csr_der_b64": csr.DER,
		"est_pkcs7_der_b64": pkcs7DER, "ca_pem": string(caPEM),
	})
	dodPQCCompleteSession(t, session, external, report, []byte("OpenSSL-ML-DSA-65|RFC9881|RFC7030"))
}

func dodRunMultiKeySPIFFEProof(t *testing.T) {
	runtime, control, external := dodStartPQCRuntime(t, "pqc_end_to_end.multikey_spiffe_hybrid_svid", func(cfg *config.Config, root string, _ *proof.ExternalSubstrate) {
		cfg.Protocols.SPIFFE = config.SPIFFEProtocol{
			Enabled: true, TenantID: dodPQCTenant, TrustDomain: "pqc.dod.test",
			SocketPath: dodPQCLocalSocketPath(t),
		}
	})
	dodPQCWaitForSocket(t, runtime.cfg.Protocols.SPIFFE.SocketPath)
	connection, err := grpc.NewClient("unix://"+runtime.cfg.Protocols.SPIFFE.SocketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(spiffe.SecurityHeaderKey, spiffe.SecurityHeaderValue))
	stream, err := workloadpb.NewSpiffeWorkloadAPIClient(connection).FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || len(response.GetSvids()) != 2 {
		t.Fatalf("hybrid X509SVIDResponse entries=%d err=%v", len(response.GetSvids()), err)
	}
	caPEM, err := os.ReadFile(runtime.caFile)
	if err != nil {
		t.Fatal(err)
	}
	svids := make([]map[string]any, 0, 2)
	for _, svid := range response.GetSvids() {
		svids = append(svids, map[string]any{
			"spiffe_id": svid.GetSpiffeId(), "hint": svid.GetHint(),
			"certificate_der_b64": svid.GetX509Svid(), "private_key_der_b64": svid.GetX509SvidKey(),
			"bundle_der_b64": svid.GetBundle(),
		})
	}
	report := dodPQCExternalJSON(t, runtime.client, external.Endpoint(), http.MethodPost, "/dod/verify", map[string]any{
		"mode": "multikey_spiffe", "ca_pem": string(caPEM), "svids": svids,
	})
	for _, svid := range response.GetSvids() {
		secret.Wipe(svid.X509SvidKey)
		svid.X509SvidKey = nil
	}
	editions, err := http.NewRequest(http.MethodGet, runtime.baseURL+"/v1/editions", nil)
	if err != nil {
		t.Fatal(err)
	}
	session := proof.StartResponse(t, "pqc_end_to_end.multikey_spiffe_hybrid_svid", control.Do(editions))
	if session.StatusCode() != http.StatusOK {
		t.Fatalf("edition anchor status=%d body=%s", session.StatusCode(), session.ResponseBody())
	}
	dodPQCCompleteSession(t, session, external, report, []byte("SPIFFE-Workload-API|classical+ML-DSA-65"))
}

func dodRunAutomatedTLSRolloutProof(t *testing.T) {
	var hostConfig string
	runtime, control, external := dodStartPQCRuntime(t, "pqc_end_to_end.automated_rollout_tls_findings", func(cfg *config.Config, root string, external *proof.ExternalSubstrate) {
		hostConfig = filepath.Join(root, "envoy-tls.conf")
		if err := os.WriteFile(hostConfig, []byte("ssl_protocols TLSv1 TLSv1.3;\nssl_ciphers TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS_AES_256_GCM_SHA384;\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.Connectors.Enabled = []string{"envoy"}
		cfg.Connectors.AllowPrivateCIDRs = []string{"127.0.0.0/8"}
		cfg.Connectors.AllowInsecureHTTP = true
		_ = external
	})
	bridge := dodRightSizeLoopbackBridge(t, external.Endpoint())
	targetBody := dodRightSizeAPIRequest(t, runtime.client, runtime.baseURL, runtime.token,
		http.MethodPost, "/api/v1/connectors/targets", "dod-pqc-target", map[string]any{
			"name": "edge-listener", "connector": "envoy",
			"config": map[string]any{"endpoint": bridge, "secret_name": "edge-cert"},
		}, http.StatusCreated)
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(targetBody, &target); err != nil || target.ID == "" {
		t.Fatalf("decode Envoy target: %v body=%s", err, targetBody)
	}
	dodRightSizeAPIRequest(t, runtime.client, runtime.baseURL, runtime.token,
		http.MethodPost, "/api/v1/cbom/scans", "dod-pqc-scan", map[string]any{
			"host_configs": []string{hostConfig},
		}, http.StatusCreated)
	var inventory struct {
		Items []struct {
			ID          string `json:"id"`
			Protocol    string `json:"protocol"`
			Cipher      string `json:"cipher"`
			OutOfPolicy bool   `json:"out_of_policy"`
		} `json:"items"`
	}
	var inventoryBody []byte
	inventoryDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(inventoryDeadline) {
		inventoryBody = dodRightSizeAPIRequest(t, runtime.client, runtime.baseURL, runtime.token,
			http.MethodGet, "/api/v1/cbom/assets", "", nil, http.StatusOK)
		inventory.Items = nil
		if err := json.Unmarshal(inventoryBody, &inventory); err != nil {
			t.Fatalf("decode CBOM inventory: %v body=%s", err, inventoryBody)
		}
		applicable := 0
		for _, item := range inventory.Items {
			if item.OutOfPolicy && (item.Protocol != "" || item.Cipher != "") {
				applicable++
			}
		}
		if applicable >= 2 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	desired := map[string]any{
		"minimum_version":     "TLSv1.3",
		"cipher_suites":       []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		"key_exchange_groups": []string{"X25519MLKEM768", "X25519"},
	}
	assetIDs := []string{}
	bindings := []map[string]any{}
	selected := []map[string]any{}
	for _, item := range inventory.Items {
		if !item.OutOfPolicy || (item.Protocol == "" && item.Cipher == "") {
			continue
		}
		kind := "cipher"
		if item.Protocol != "" {
			kind = "protocol"
		}
		assetIDs = append(assetIDs, item.ID)
		bindings = append(bindings, map[string]any{"asset_id": item.ID, "target_id": target.ID, "desired": desired})
		selected = append(selected, map[string]any{"asset_id": item.ID, "finding_kind": kind})
	}
	if len(assetIDs) != 2 {
		t.Fatalf("applicable TLS finding count=%d, want exact protocol+cipher; inventory=%s", len(assetIDs), inventoryBody)
	}
	startBody := dodRightSizeAPIRequest(t, runtime.client, runtime.baseURL, runtime.token,
		http.MethodPost, "/api/v1/pqc/migrations", "dod-pqc-rollout", map[string]any{
			"asset_ids": assetIDs, "target_algorithm": "ML-DSA-65", "protocol": "acme",
			"rollback_on_failure": true, "tls_bindings": bindings,
		}, http.StatusAccepted)
	var started struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(startBody, &started); err != nil || started.RunID == "" {
		t.Fatalf("decode PQC rollout start: %v body=%s", err, startBody)
	}
	applied := dodPQCWaitProgress(t, runtime, started.RunID, func(progress map[string]any) bool {
		return number(progress["total"]) == 2 && number(progress["applied"]) == 2 && number(progress["queued"]) == 0 && number(progress["failed"]) == 0
	})
	cbomRequest, err := http.NewRequest(http.MethodGet, runtime.baseURL+"/api/v1/cbom/assets", nil)
	if err != nil {
		t.Fatal(err)
	}
	cbomRequest.Header.Set("Authorization", "Bearer "+runtime.token)
	session := proof.StartResponse(t, "pqc_end_to_end.automated_rollout_tls_findings", control.Do(cbomRequest))
	if session.StatusCode() != http.StatusOK {
		t.Fatalf("migrated CBOM status=%d body=%s", session.StatusCode(), session.ResponseBody())
	}
	var migrated struct {
		Items []struct {
			ID          string `json:"id"`
			Protocol    string `json:"protocol"`
			Cipher      string `json:"cipher"`
			OutOfPolicy bool   `json:"out_of_policy"`
		} `json:"items"`
	}
	if err := json.Unmarshal(session.ResponseBody(), &migrated); err != nil {
		t.Fatalf("decode migrated CBOM: %v body=%s", err, session.ResponseBody())
	}
	migratedByID := make(map[string]struct {
		Protocol    string
		Cipher      string
		OutOfPolicy bool
	}, len(migrated.Items))
	for _, item := range migrated.Items {
		migratedByID[item.ID] = struct {
			Protocol    string
			Cipher      string
			OutOfPolicy bool
		}{Protocol: item.Protocol, Cipher: item.Cipher, OutOfPolicy: item.OutOfPolicy}
	}
	protocolMigrated, cipherMigrated := false, false
	for _, item := range migrated.Items {
		if !item.OutOfPolicy && item.Protocol == "TLSv1.3" {
			protocolMigrated = true
		}
		if !item.OutOfPolicy && strings.Contains(item.Cipher, "TLS_AES_256_GCM_SHA384") {
			cipherMigrated = true
		}
	}
	for _, assetID := range assetIDs {
		if item, ok := migratedByID[assetID]; ok && item.OutOfPolicy {
			t.Fatalf("selected finding %s remained out of policy after applied progress: %+v", assetID, item)
		}
	}
	if !protocolMigrated || !cipherMigrated {
		t.Fatalf("migrated inventory lacks canonical TLSv1.3+cipher facts: %s", session.ResponseBody())
	}
	dodRightSizeAPIRequest(t, runtime.client, runtime.baseURL, runtime.token,
		http.MethodPost, "/api/v1/pqc/migrations/"+started.RunID+"/rollback", "dod-pqc-rollback", map[string]any{
			"asset_ids": assetIDs, "reason": "DoD exact rollback",
		}, http.StatusAccepted)
	rolledBack := dodPQCWaitProgress(t, runtime, started.RunID, func(progress map[string]any) bool {
		return number(progress["total"]) == 2 && number(progress["rolled_back"]) == 2 && number(progress["queued"]) == 0
	})
	legacy := map[string]any{
		"minimum_version":     "TLSv1.0",
		"cipher_suites":       []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		"key_exchange_groups": []string{"secp256r1"},
	}
	report := dodPQCExternalJSON(t, runtime.client, external.Endpoint(), http.MethodPost, "/dod/verify", map[string]any{
		"mode": "automated_tls_rollout", "selected_findings": selected,
		"applied_progress": applied, "rollback_progress": rolledBack,
		"desired": desired, "legacy": legacy,
	})
	dodPQCCompleteSession(t, session, external, report, []byte("CBOM|sealed-outbox|Envoy-readback|exact-rollback"))
}

func dodPQCWaitProgress(t *testing.T, runtime *dodPQCRuntime, runID string, accept func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		last = dodRightSizeAPIRequest(t, runtime.client, runtime.baseURL, runtime.token,
			http.MethodGet, "/api/v1/pqc/migrations/"+runID, "", nil, http.StatusOK)
		var progress map[string]any
		if json.Unmarshal(last, &progress) == nil && accept(progress) {
			return progress
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("PQC progress did not converge: %s", last)
	return nil
}

func number(value any) int {
	switch n := value.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return -1
	}
}

func dodPQCExternalJSON(t *testing.T, client *http.Client, endpoint, method, path string, value any) []byte {
	t.Helper()
	var body io.Reader
	var raw []byte
	if value != nil {
		var err error
		raw, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, endpoint+path, body)
	if err != nil {
		secret.Wipe(raw)
		t.Fatal(err)
	}
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	secret.Wipe(raw)
	if err != nil {
		t.Fatalf("external PQC %s %s: %v", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	result, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("external PQC %s %s status=%d body=%s", method, path, response.StatusCode, result)
	}
	return result
}

func dodPQCWaitForSocket(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("SPIFFE Workload API socket %q did not become ready", socket)
}

// dodPQCLocalSocketPath keeps the Workload API socket on the shipped
// runtime's local filesystem. The proof root is a parent-owned Docker Desktop
// bind mount so receipts survive the container, but that mount cannot reliably
// carry a Linux Unix-domain socket. Production also defaults the Workload API
// socket to /tmp, so this preserves the deployed topology while isolating
// concurrent proof processes.
func dodPQCLocalSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "trstctl-dod-pqc-spiffe-")
	if err != nil {
		t.Fatalf("create runtime-local PQC SPIFFE socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "workload.sock")
}

func dodPQCCompleteSession(t *testing.T, session *proof.Session, external *proof.ExternalSubstrate, report, clientIdentity []byte) {
	t.Helper()
	readback := dodPQCExternalJSON(t, &http.Client{Timeout: 10 * time.Second}, external.Endpoint(), http.MethodGet, "/dod/readback", nil)
	if !bytes.Equal(report, readback) {
		t.Fatal("independent PQC verifier readback differs from accepted report")
	}
	contract, err := os.ReadFile("../../tools/dodcensus/contracts/pqc-interop-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity: clientIdentity, Transcript: append(append([]byte(nil), report...), contract...),
		IndependentVerifier: readback, ExecutionReceipt: executionReceipt,
	}))
}
