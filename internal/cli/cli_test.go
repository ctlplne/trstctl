package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cli"
)

// TestEveryAPIOperationHasACLICommand is the S7.1 acceptance: every core API
// operation has a CLI command.
func TestEveryAPIOperationHasACLICommand(t *testing.T) {
	have := map[string]bool{}
	for _, c := range cli.Commands() {
		have[c.Method+" "+c.Path] = true
	}
	for _, r := range api.New(nil, nil, nil).Routes() {
		if r.Path == "/api/v1/openapi.json" {
			continue // the spec endpoint is not a core operation
		}
		if !have[r.Method+" "+r.Path] {
			t.Errorf("no CLI command for API operation %s %s", r.Method, r.Path)
		}
	}
}

// capture records the request the CLI sent.
type capture struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

func mockServer(t *testing.T, status int, respBody string, cap *capture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.Method, cap.Path, cap.Query, cap.Header, cap.Body = r.Method, r.URL.Path, r.URL.RawQuery, r.Header, b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, args []string, env cli.Env, stdin string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = cli.Run(context.Background(), args, env, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestListSendsAuthAndPrintsJSON(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"certificates":[]}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-123", Tenant: "tenant-1", HTTPClient: srv.Client()}

	code, stdout, _ := run(t, []string{"certificates", "list"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/certificates" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-1" {
		t.Errorf("X-Tenant-ID = %q", cap.Header.Get("X-Tenant-ID"))
	}
	var j any
	if err := json.Unmarshal([]byte(stdout), &j); err != nil {
		t.Errorf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

func TestGetSubstitutesPathParam(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"id":"abc-123"}`, &cap)
	code, _, _ := run(t, []string{"owners", "get", "abc-123"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Path != "/api/v1/owners/abc-123" {
		t.Errorf("path = %q, want /api/v1/owners/abc-123", cap.Path)
	}
}

func TestCreateSendsBodyFromStdin(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"id":"new"}`, &cap)
	body := `{"kind":"workload","name":"svc"}`
	code, _, _ := run(t, []string{"owners", "create", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/owners" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestAttestedIssuanceCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","credential_id":"cred:test","subject":"ns/default/sa/web","not_after":"2026-06-24T12:00:00Z","attestation":{"id":"att:k8s","method":"k8s_sat","subject":"ns/default/sa/web","issuer":"kubernetes","expires_at":"2026-06-24T12:00:00Z","verified_at":"2026-06-24T11:50:00Z"}}`, &cap)
	body := `{"method":"k8s_sat","payload_base64":"c2F0","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0DrbFLt03cHuBfOfvt/wL6+9Yv5mzn4XLu9WLCrCx0o=\n-----END PUBLIC KEY-----\n","ttl_seconds":600}`
	code, _, _ := run(t, []string{"workloads", "attested-issuance", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/workloads/attested-issuance" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("attested issuance mutation should send an Idempotency-Key")
	}
}

func TestBrokerAgentIdentityCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"agent_id":"agent-7","node_id":"wl:agent-7","subject":"agent-7","credential_id":"cred:test","certificate_id":"cert:test","certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","scopes":["mcp:graph.read"],"not_after":"2026-06-24T12:00:00Z","attestation":{"id":"att:broker","method":"stub_broker","subject":"agent-7","issuer":"broker","expires_at":"2026-06-24T12:00:00Z","verified_at":"2026-06-24T11:50:00Z"}}`, &cap)
	body := `{"agent_id":"agent-7","method":"stub_broker","payload_base64":"Z2VudWluZQ==","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0DrbFLt03cHuBfOfvt/wL6+9Yv5mzn4XLu9WLCrCx0o=\n-----END PUBLIC KEY-----\n","scopes":["mcp:graph.read"],"ttl_seconds":600}`
	code, _, _ := run(t, []string{"broker", "agent-identities", "issue", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/broker/agent-identities" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("broker identity issuance mutation should send an Idempotency-Key")
	}
}

func TestEphemeralCommandsSendBodiesAndIdempotencyKeys(t *testing.T) {
	var issueCap capture
	issueSrv := mockServer(t, 202, `{"state":"awaiting_approval","request_id":"jit-agent-7","subject":"jit-agent-7","required_approvals":1,"approvals":0,"expires_at":"2026-06-24T12:00:00Z","attestation":{"id":"att:jit","method":"stub_ephemeral","subject":"jit-agent-7","issuer":"jit","expires_at":"2026-06-24T12:00:00Z","verified_at":"2026-06-24T11:50:00Z"}}`, &issueCap)
	issueBody := `{"request_id":"jit-agent-7","method":"stub_ephemeral","payload_base64":"Z2VudWluZQ==","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0DrbFLt03cHuBfOfvt/wL6+9Yv5mzn4XLu9WLCrCx0o=\n-----END PUBLIC KEY-----\n","ttl_seconds":120}`
	code, _, _ := run(t, []string{"ephemeral", "issue", "-f", "-"}, cli.Env{Server: issueSrv.URL, HTTPClient: issueSrv.Client()}, issueBody)
	if code != 0 {
		t.Fatalf("issue exit = %d", code)
	}
	if issueCap.Method != "POST" || issueCap.Path != "/api/v1/ephemeral" {
		t.Errorf("issue request = %s %s", issueCap.Method, issueCap.Path)
	}
	if strings.TrimSpace(string(issueCap.Body)) != issueBody {
		t.Errorf("issue body = %q, want %q", issueCap.Body, issueBody)
	}
	if issueCap.Header.Get("Idempotency-Key") == "" {
		t.Error("ephemeral issue mutation should send an Idempotency-Key")
	}

	var approveCap capture
	approveSrv := mockServer(t, 200, `{"resource":"jit-agent-7","action":"issue","approver":"ra-1","approvals":1}`, &approveCap)
	approveBody := `{"action":"issue"}`
	code, _, _ = run(t, []string{"ephemeral", "approve", "jit-agent-7", "-f", "-"}, cli.Env{Server: approveSrv.URL, HTTPClient: approveSrv.Client()}, approveBody)
	if code != 0 {
		t.Fatalf("approve exit = %d", code)
	}
	if approveCap.Method != "POST" || approveCap.Path != "/api/v1/ephemeral/jit-agent-7/approvals" {
		t.Errorf("approve request = %s %s", approveCap.Method, approveCap.Path)
	}
	if strings.TrimSpace(string(approveCap.Body)) != approveBody {
		t.Errorf("approve body = %q, want %q", approveCap.Body, approveBody)
	}
	if approveCap.Header.Get("Idempotency-Key") == "" {
		t.Error("ephemeral approve mutation should send an Idempotency-Key")
	}
}

func TestMachineLoginCommandSendsCredentialBody(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"session_id":"sess-1","principal":"spiffe://example/workload","method":"token","scopes":[],"expires_at":"2026-06-17T12:00:00Z"}`, &cap)
	body := `{"credential":"machine-token","method":"token"}`
	code, _, _ := run(t, []string{"secrets", "login", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/login" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("machine login mutation should send an Idempotency-Key")
	}
}

func TestStaticRotationCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"key":"db/reporting","old_ref":"old","new_ref":"new","completed":true}`, &cap)
	body := `{"provider":"postgresql","key":"db/reporting","old_ref":"old"}`
	code, _, _ := run(t, []string{"secrets", "rotations", "run", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/rotations" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("static rotation mutation should send an Idempotency-Key")
	}
}

func TestSecretSyncCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD","enqueued":true,"delivered":true}`, &cap)
	body := `{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}`
	code, _, _ := run(t, []string{"secrets", "syncs", "run", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/syncs" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("secret sync mutation should send an Idempotency-Key")
	}
}

func TestSecretScanCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"run_id":"1f95f7db-4a45-40fe-bb8f-9b7dfc8f6ad8","scanner":"gitleaks","engine_version":"v8.27.2","rules_active":213,"findings_count":1,"findings":[]}`, &cap)
	body := `{"path":"."}`
	code, _, _ := run(t, []string{"secrets", "scans", "run", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/scans" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("secret scan mutation should send an Idempotency-Key")
	}
}

func TestRunInjectsFetchedSecretsIntoChildEnvWithoutLoggingValues(t *testing.T) {
	envPath, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env command not available")
	}
	var cap capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.Method, cap.Path, cap.Query, cap.Header, cap.Body = r.Method, r.URL.Path, r.URL.RawQuery, r.Header, b
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/secrets/store/db/password" {
			http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"name":"db/password","value":"s3cr3t","version":1}`)
	}))
	t.Cleanup(srv.Close)

	code, stdout, stderr := run(t, []string{"run", "--secret", "DB_PASSWORD=db/password", "--", envPath}, cli.Env{Server: srv.URL, Token: "tok-123", Tenant: "tenant-1", HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if cap.Method != http.MethodGet || cap.Path != "/api/v1/secrets/store/db/password" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-1" {
		t.Errorf("X-Tenant-ID = %q", cap.Header.Get("X-Tenant-ID"))
	}
	if !strings.Contains(stdout, "DB_PASSWORD=s3cr3t") {
		t.Fatalf("stdout does not include injected secret env var:\n%s", stdout)
	}
	if strings.Contains(stderr, "s3cr3t") {
		t.Fatalf("stderr leaked secret material: %q", stderr)
	}
}

func TestQueryFlag(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{}`, &cap)
	code, _, _ := run(t, []string{"certificates", "list", "--limit", "5"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Query != "limit=5" {
		t.Errorf("query = %q, want limit=5", cap.Query)
	}
}

func TestCBOMScanCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"items":[],"migration_progress":{"total":0,"post_quantum_ready":0,"quantum_vulnerable":0,"percent_ready":100}}`, &cap)
	body := `{"tls_endpoints":["payments.internal:443"],"host_configs":["/etc/nginx/site.conf"]}`
	code, _, _ := run(t, []string{"cbom", "scan", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/cbom/scans" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("CBOM scan mutation should send an Idempotency-Key")
	}
}

func TestCBOMAssetsCommandReadsInventory(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"items":[],"migration_progress":{"total":0,"post_quantum_ready":0,"quantum_vulnerable":0,"percent_ready":100}}`, &cap)
	code, stdout, _ := run(t, []string{"cbom", "assets"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/cbom/assets" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	var j any
	if err := json.Unmarshal([]byte(stdout), &j); err != nil {
		t.Errorf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

func TestPQCMigrationStartCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 202, `{"run_id":"11111111-1111-4111-8111-111111111111","queued":1}`, &cap)
	body := `{"asset_ids":["22222222-2222-4222-8222-222222222222"],"target_algorithm":"ML-DSA-65","protocol":"acme","rollback_on_failure":true}`
	code, _, _ := run(t, []string{"pqc", "migrations", "start", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/pqc/migrations" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("PQC migration start should send an Idempotency-Key")
	}
}

func TestPQCMigrationRollbackCommandSendsRunIDBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 202, `{"run_id":"11111111-1111-4111-8111-111111111111","queued":1}`, &cap)
	body := `{"asset_ids":["22222222-2222-4222-8222-222222222222"],"reason":"rollback drill"}`
	code, _, _ := run(t, []string{"pqc", "migrations", "rollback", "11111111-1111-4111-8111-111111111111", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/pqc/migrations/11111111-1111-4111-8111-111111111111/rollback" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("PQC migration rollback should send an Idempotency-Key")
	}
}

func TestConnectorsOutboxCircuitsCommand(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"circuits":[]}`, &cap)
	code, _, _ := run(t, []string{"connectors", "outbox-circuits"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/connectors/outbox-circuits" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
}

func TestGraphQueryWrapsCypher(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"rows":[]}`, &cap)
	code, _, _ := run(t, []string{"graph", "query", "MATCH (n) RETURN n"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/graph/query" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	var got struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(cap.Body, &got); err != nil || got.Query != "MATCH (n) RETURN n" {
		t.Errorf("body = %q, want a {query} wrapper", cap.Body)
	}
}

func TestErrorExitCode(t *testing.T) {
	var cap capture
	srv := mockServer(t, 404, `{"detail":"not found"}`, &cap)
	code, _, stderr := run(t, []string{"owners", "get", "missing"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code == 0 {
		t.Error("a 404 should exit non-zero")
	}
	if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "404") {
		t.Errorf("stderr should explain the error: %q", stderr)
	}
}

func TestMissingServerErrors(t *testing.T) {
	code, _, _ := run(t, []string{"owners", "list"}, cli.Env{}, "")
	if code == 0 {
		t.Error("missing --server should exit non-zero")
	}
}

func TestUnknownCommandErrors(t *testing.T) {
	code, _, _ := run(t, []string{"bogus", "thing"}, cli.Env{Server: "http://x"}, "")
	if code == 0 {
		t.Error("unknown command should exit non-zero")
	}
}
