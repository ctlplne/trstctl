package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

func TestNHIInventoryCommandSendsAuthAndPrintsJSON(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"items":[],"summary":{"total":0},"coverage":[]}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-123", Tenant: "tenant-1", HTTPClient: srv.Client()}

	code, stdout, _ := run(t, []string{"nhi", "inventory"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/nhi/inventory" {
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

func TestDestructiveCommandRequiresForce(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"revoked":1}`, &cap)
	body := `{"ids":["identity-1"]}`

	code, _, stderr := run(t, []string{"identities", "bulk-revoke", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "destructive") || !strings.Contains(stderr, "--force") {
		t.Fatalf("stderr = %q, want destructive --force guidance", stderr)
	}
	if cap.Method != "" {
		t.Fatalf("destructive command reached server without force: %s %s", cap.Method, cap.Path)
	}
}

func TestDestructiveCommandSucceedsWithForce(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"revoked":1}`, &cap)
	body := `{"ids":["identity-1"]}`

	code, _, stderr := run(t, []string{"identities", "bulk-revoke", "--force", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/identities/bulk-revoke" {
		t.Fatalf("request = %s %s, want POST /api/v1/identities/bulk-revoke", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("destructive mutation should still send an Idempotency-Key")
	}
}

func TestCommandHelpIncludesExampleForEveryAPIOperation(t *testing.T) {
	for _, cmd := range cli.Commands() {
		if strings.Join(cmd.Name, " ") == "run" {
			continue
		}
		args := append(append([]string{}, cmd.Name...), "--help")
		code, stdout, stderr := run(t, args, cli.Env{}, "")
		if code != 0 {
			t.Fatalf("%s --help exit = %d, stderr = %q", strings.Join(cmd.Name, " "), code, stderr)
		}
		if !strings.Contains(stdout, "Usage: trstctl "+strings.Join(cmd.Name, " ")) {
			t.Errorf("%s --help missing usage: %q", strings.Join(cmd.Name, " "), stdout)
		}
		if !strings.Contains(stdout, "Example: trstctl "+strings.Join(cmd.Name, " ")) {
			t.Errorf("%s --help missing example: %q", strings.Join(cmd.Name, " "), stdout)
		}
		if cmd.Destructive() && !strings.Contains(stdout, "--force") {
			t.Errorf("%s --help missing --force warning in usage/example: %q", strings.Join(cmd.Name, " "), stdout)
		}
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

func TestCAAuthorityIssueIntermediateCSRCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","serial":"01","not_after":"2026-06-24T12:00:00Z"}`, &cap)
	body := `{"ceremony_id":"ceremony-1","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n","spec":{"common_name":"SPIRE Server CA","ttl_seconds":3600,"max_path_len":0}}`
	code, _, _ := run(t, []string{"ca", "authorities", "issue-intermediate-csr", "root-1", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/ca/authorities/root-1/intermediates/csr" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("intermediate CSR issuance mutation should send an Idempotency-Key")
	}
}

func TestCAAuthorityRotateCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"issue_path":"/api/v1/ca/authorities/ca-old/issue","active_issue_path":"/api/v1/ca/authorities/ca-new/issue"}`, &cap)
	body := `{"successor_id":"ca-new","reason":"planned overlap"}`
	code, _, _ := run(t, []string{"ca", "authorities", "rotate", "ca-old", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/ca/authorities/ca-old/rotate" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("CA rotation mutation should send an Idempotency-Key")
	}
}

func TestCAAuthorityRekeyCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"issue_path":"/api/v1/ca/authorities/ca-old/issue","active_issue_path":"/api/v1/ca/authorities/ca-new/issue"}`, &cap)
	body := `{"ceremony_id":"ceremony-1","ttl_seconds":15552000,"reason":"planned renewal"}`
	code, _, _ := run(t, []string{"ca", "authorities", "rekey", "ca-old", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/ca/authorities/ca-old/rekey" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("CA re-key mutation should send an Idempotency-Key")
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

func TestAccessSessionCommandsSendBodiesQueriesAndIdempotencyKeys(t *testing.T) {
	var openCap capture
	openSrv := mockServer(t, 201, `{"id":"pam:session-1","target_type":"postgres","target_id":"prod-db","status":"active"}`, &openCap)
	openBody := `{"target_type":"postgres","target_id":"prod-db","role":"read_only","reason":"incident cleanup","attestation":{"method":"stub","subject":"ops@example.com","payload_base64":"Z2VudWluZQ=="}}`
	code, _, _ := run(t, []string{"access", "sessions", "open", "-f", "-"}, cli.Env{Server: openSrv.URL, HTTPClient: openSrv.Client()}, openBody)
	if code != 0 {
		t.Fatalf("open exit = %d", code)
	}
	if openCap.Method != "POST" || openCap.Path != "/api/v1/access/sessions" {
		t.Errorf("open request = %s %s", openCap.Method, openCap.Path)
	}
	if strings.TrimSpace(string(openCap.Body)) != openBody {
		t.Errorf("open body = %q, want %q", openCap.Body, openBody)
	}
	if openCap.Header.Get("Idempotency-Key") == "" {
		t.Error("access session open should send an Idempotency-Key")
	}

	var listCap capture
	listSrv := mockServer(t, 200, `{"sessions":[]}`, &listCap)
	code, _, _ = run(t, []string{"access", "sessions", "list", "--limit", "3", "--cursor", "next"}, cli.Env{Server: listSrv.URL, HTTPClient: listSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if listCap.Method != "GET" || listCap.Path != "/api/v1/access/sessions" || listCap.Query != "cursor=next&limit=3" {
		t.Errorf("list request = %s %s?%s", listCap.Method, listCap.Path, listCap.Query)
	}
	if listCap.Header.Get("Idempotency-Key") != "" {
		t.Error("access session list must not send an Idempotency-Key")
	}

	var getCap capture
	getSrv := mockServer(t, 200, `{"id":"pam:session-1"}`, &getCap)
	code, _, _ = run(t, []string{"access", "sessions", "get", "pam:session-1"}, cli.Env{Server: getSrv.URL, HTTPClient: getSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("get exit = %d", code)
	}
	if getCap.Method != "GET" || getCap.Path != "/api/v1/access/sessions/pam:session-1" {
		t.Errorf("get request = %s %s", getCap.Method, getCap.Path)
	}
}

func TestBreakglassReconcileCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"reconciled":1}`, &cap)
	body := `{"bundles":[{"request_id":"bg-1","subject":"svc.example","cert_der":"Y2VydA==","reason":"restore production","approvals":["alice"],"issued_at":"2026-06-25T17:00:00Z","signature":"c2ln"}]}`
	code, _, _ := run(t, []string{"breakglass", "reconcile", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/breakglass/reconcile" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("break-glass reconcile mutation should send an Idempotency-Key")
	}
}

func TestBreakglassIssueCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"reconciled":1,"audit_event_type":"breakglass.issued"}`, &cap)
	body := `{"request_id":"bg-online-1","subject":"svc.example","csr_der":"Y3Ny","reason":"restore production","approvals":["alice","bob"],"ttl_seconds":900}`
	code, _, _ := run(t, []string{"breakglass", "issue", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/breakglass/issue" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("break-glass issue mutation should send an Idempotency-Key")
	}
}

func TestServiceNowTicketCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 202, `{"id":"ticket-1","status":"queued"}`, &cap)
	body := `{"instance_url":"https://example.service-now.com","table":"incident","token_ref":"env:TRSTCTL_SERVICENOW_TOKEN","short_description":"Rotate exposed TLS private key"}`
	code, _, _ := run(t, []string{"itsm", "servicenow", "tickets", "create", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/itsm/servicenow/tickets" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("ServiceNow ticket mutation should send an Idempotency-Key")
	}
}

func TestFleetReissuanceCommandsSendBodiesQueriesAndIdempotencyKeys(t *testing.T) {
	var startCap capture
	startSrv := mockServer(t, 201, `{"id":"fleet-1","status":"executed"}`, &startCap)
	startBody := `{"issuer_id":"issuer-1","reason":"compromised intermediate","batch_size":10}`
	code, _, _ := run(t, []string{"incidents", "fleet-reissuance", "start", "-f", "-"}, cli.Env{Server: startSrv.URL, HTTPClient: startSrv.Client()}, startBody)
	if code != 0 {
		t.Fatalf("start exit = %d", code)
	}
	if startCap.Method != "POST" || startCap.Path != "/api/v1/incidents/fleet-reissuance-runs" {
		t.Errorf("start request = %s %s", startCap.Method, startCap.Path)
	}
	if strings.TrimSpace(string(startCap.Body)) != startBody {
		t.Errorf("start body = %q, want %q", startCap.Body, startBody)
	}
	if startCap.Header.Get("Idempotency-Key") == "" {
		t.Error("fleet reissuance start mutation should send an Idempotency-Key")
	}

	var listCap capture
	listSrv := mockServer(t, 200, `{"items":[]}`, &listCap)
	code, _, _ = run(t, []string{"incidents", "fleet-reissuance", "list", "--issuer_id", "issuer-1", "--limit", "5"}, cli.Env{Server: listSrv.URL, HTTPClient: listSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if listCap.Method != "GET" || listCap.Path != "/api/v1/incidents/fleet-reissuance-runs" {
		t.Errorf("list request = %s %s", listCap.Method, listCap.Path)
	}
	if !strings.Contains(listCap.Query, "issuer_id=issuer-1") || !strings.Contains(listCap.Query, "limit=5") {
		t.Errorf("list query = %q, want issuer_id and limit", listCap.Query)
	}
	if listCap.Header.Get("Idempotency-Key") != "" {
		t.Error("fleet reissuance list must not send an Idempotency-Key")
	}

	var pauseCap capture
	pauseSrv := mockServer(t, 200, `{"id":"fleet-1","status":"paused"}`, &pauseCap)
	pauseBody := `{"reason":"operator inspection"}`
	code, _, _ = run(t, []string{"incidents", "fleet-reissuance", "pause", "fleet-1", "-f", "-"}, cli.Env{Server: pauseSrv.URL, HTTPClient: pauseSrv.Client()}, pauseBody)
	if code != 0 {
		t.Fatalf("pause exit = %d", code)
	}
	if pauseCap.Method != "POST" || pauseCap.Path != "/api/v1/incidents/fleet-reissuance-runs/fleet-1/pause" {
		t.Errorf("pause request = %s %s", pauseCap.Method, pauseCap.Path)
	}
	if strings.TrimSpace(string(pauseCap.Body)) != pauseBody {
		t.Errorf("pause body = %q, want %q", pauseCap.Body, pauseBody)
	}
	if pauseCap.Header.Get("Idempotency-Key") == "" {
		t.Error("fleet reissuance pause mutation should send an Idempotency-Key")
	}

	var evidenceCap capture
	evidenceSrv := mockServer(t, 200, `{"run_id":"fleet-1"}`, &evidenceCap)
	code, _, _ = run(t, []string{"incidents", "fleet-reissuance", "evidence", "fleet-1"}, cli.Env{Server: evidenceSrv.URL, HTTPClient: evidenceSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("evidence exit = %d", code)
	}
	if evidenceCap.Method != "GET" || evidenceCap.Path != "/api/v1/incidents/fleet-reissuance-runs/fleet-1/evidence" {
		t.Errorf("evidence request = %s %s", evidenceCap.Method, evidenceCap.Path)
	}
	if evidenceCap.Header.Get("Idempotency-Key") != "" {
		t.Error("fleet reissuance evidence export must not send an Idempotency-Key")
	}
}

func TestManagedOfferingCommandsSendStatusAndProvisionTenant(t *testing.T) {
	var statusCap capture
	statusSrv := mockServer(t, 200, `{"served":true,"deployment_model":"managed_provider","provider_plane_mode":"enabled"}`, &statusCap)
	code, _, _ := run(t, []string{"managed-offering", "status"}, cli.Env{Server: statusSrv.URL, HTTPClient: statusSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("status exit = %d", code)
	}
	if statusCap.Method != "GET" || statusCap.Path != "/api/v1/managed-offering/status" {
		t.Errorf("status request = %s %s", statusCap.Method, statusCap.Path)
	}
	if statusCap.Header.Get("Idempotency-Key") != "" {
		t.Error("status command must not send an Idempotency-Key")
	}

	var provisionCap capture
	provisionSrv := mockServer(t, 201, `{"tenant_id":"22222222-2222-4222-8222-222222222222","managed":true}`, &provisionCap)
	body := `{"tenant_id":"22222222-2222-4222-8222-222222222222","name":"Acme Hosted","region":"us-east-1","data_residency":"US","plan":"enterprise","support_tier":"24x7","slo_tier":"99.95"}`
	code, _, _ = run(t, []string{"managed-offering", "tenants", "provision", "-f", "-"}, cli.Env{Server: provisionSrv.URL, HTTPClient: provisionSrv.Client()}, body)
	if code != 0 {
		t.Fatalf("provision exit = %d", code)
	}
	if provisionCap.Method != "POST" || provisionCap.Path != "/api/v1/managed-offering/tenants" {
		t.Errorf("provision request = %s %s", provisionCap.Method, provisionCap.Path)
	}
	if strings.TrimSpace(string(provisionCap.Body)) != body {
		t.Errorf("body = %q, want %q", provisionCap.Body, body)
	}
	if provisionCap.Header.Get("Idempotency-Key") == "" {
		t.Error("managed offering provision mutation should send an Idempotency-Key")
	}
}

func TestEnterpriseSupportCommandSendsReadOnlyStatusRequest(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"served":true,"capability":"CAP-MODEL-04","support_mode":"enabled"}`, &cap)
	code, _, _ := run(t, []string{"support", "enterprise"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/support/enterprise" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "" {
		t.Error("enterprise support status command must not send an Idempotency-Key")
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

func TestSecretRotationScheduleCommandsSendPathsAndIdempotencyKeys(t *testing.T) {
	var createCap capture
	srv := mockServer(t, 201, `{"id":"11111111-1111-1111-1111-111111111111","name":"reporting-hourly","provider":"postgresql","key":"db/reporting","old_ref":"old","interval_seconds":3600,"enabled":true,"next_run_at":"2026-07-01T00:00:00Z","last_run_status":"","created_at":"2026-07-01T00:00:00Z","updated_at":"2026-07-01T00:00:00Z"}`, &createCap)
	body := `{"name":"reporting-hourly","provider":"postgresql","key":"db/reporting","old_ref":"old","interval_seconds":3600}`
	code, _, _ := run(t, []string{"secrets", "rotation-schedules", "create", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("create exit = %d", code)
	}
	if createCap.Method != "POST" || createCap.Path != "/api/v1/secrets/rotation-schedules" {
		t.Errorf("create request = %s %s", createCap.Method, createCap.Path)
	}
	if strings.TrimSpace(string(createCap.Body)) != body {
		t.Errorf("create body = %q, want %q", createCap.Body, body)
	}
	if createCap.Header.Get("Idempotency-Key") == "" {
		t.Error("rotation schedule create should send an Idempotency-Key")
	}

	var listCap capture
	srv = mockServer(t, 200, `{"items":[]}`, &listCap)
	code, _, _ = run(t, []string{"secrets", "rotation-schedules", "list", "--limit", "10"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if listCap.Method != "GET" || listCap.Path != "/api/v1/secrets/rotation-schedules" || listCap.Query != "limit=10" {
		t.Errorf("list request = %s %s?%s", listCap.Method, listCap.Path, listCap.Query)
	}
	if listCap.Header.Get("Idempotency-Key") != "" {
		t.Error("rotation schedule list must not send an Idempotency-Key")
	}

	var runDueCap capture
	srv = mockServer(t, 200, `{"ran":0,"runs":[]}`, &runDueCap)
	code, _, _ = run(t, []string{"secrets", "rotation-schedules", "run-due"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("run-due exit = %d", code)
	}
	if runDueCap.Method != "POST" || runDueCap.Path != "/api/v1/secrets/rotation-schedules/run-due" {
		t.Errorf("run-due request = %s %s", runDueCap.Method, runDueCap.Path)
	}
	if runDueCap.Header.Get("Idempotency-Key") == "" {
		t.Error("rotation schedule run-due should send an Idempotency-Key")
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

func TestSecretRepositoryScanCommandsMapToServedRoutes(t *testing.T) {
	var posture capture
	postureSrv := mockServer(t, 200, `{"capability":"CAP-SCAN-01","served":true}`, &posture)
	code, _, _ := run(t, []string{"secrets", "scans", "repositories"}, cli.Env{Server: postureSrv.URL, HTTPClient: postureSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("posture exit = %d", code)
	}
	if posture.Method != "GET" || posture.Path != "/api/v1/secrets/scans/repositories" {
		t.Errorf("posture request = %s %s", posture.Method, posture.Path)
	}

	var webhook capture
	webhookSrv := mockServer(t, 202, `{"capability":"CAP-SCAN-01","queued":true}`, &webhook)
	body := `{"repository":"acme/payments","checkout_path":"."}`
	code, _, _ = run(t, []string{"secrets", "scans", "repositories", "webhook", "github", "-f", "-"}, cli.Env{Server: webhookSrv.URL, HTTPClient: webhookSrv.Client()}, body)
	if code != 0 {
		t.Fatalf("webhook exit = %d", code)
	}
	if webhook.Method != "POST" || webhook.Path != "/api/v1/secrets/scans/repositories/github/webhook" {
		t.Errorf("webhook request = %s %s", webhook.Method, webhook.Path)
	}
	if strings.TrimSpace(string(webhook.Body)) != body {
		t.Errorf("webhook body = %q, want %q", webhook.Body, body)
	}
	if webhook.Header.Get("Idempotency-Key") == "" {
		t.Error("repository webhook mutation should send an Idempotency-Key")
	}
}

func TestThirdPartySecretScanCommandsMapToServedRoutes(t *testing.T) {
	var posture capture
	postureSrv := mockServer(t, 200, `{"capability":"CAP-SCAN-04","served":true}`, &posture)
	code, _, _ := run(t, []string{"secrets", "scans", "third-party"}, cli.Env{Server: postureSrv.URL, HTTPClient: postureSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("posture exit = %d", code)
	}
	if posture.Method != "GET" || posture.Path != "/api/v1/secrets/scans/third-party" {
		t.Errorf("posture request = %s %s", posture.Method, posture.Path)
	}

	var ingest capture
	ingestSrv := mockServer(t, 202, `{"capability":"CAP-SCAN-04","queued":true}`, &ingest)
	body := `{"source":"acme/slack","artifact_path":"/tmp/slack-export.jsonl"}`
	code, _, _ = run(t, []string{"secrets", "scans", "third-party", "ingest", "slack", "-f", "-"}, cli.Env{Server: ingestSrv.URL, HTTPClient: ingestSrv.Client()}, body)
	if code != 0 {
		t.Fatalf("ingest exit = %d", code)
	}
	if ingest.Method != "POST" || ingest.Path != "/api/v1/secrets/scans/third-party/slack/ingest" {
		t.Errorf("ingest request = %s %s", ingest.Method, ingest.Path)
	}
	if strings.TrimSpace(string(ingest.Body)) != body {
		t.Errorf("ingest body = %q, want %q", ingest.Body, body)
	}
	if ingest.Header.Get("Idempotency-Key") == "" {
		t.Error("third-party ingest mutation should send an Idempotency-Key")
	}
}

func TestSecretScanStagedDiffRunsLocallyWithoutServerAndRedacts(t *testing.T) {
	repo := initCLIGitRepo(t)
	writeCLIGitFile(t, repo, "app.env", "API_KEY=abc123-secret-value\n")
	gitCLI(t, repo, "add", "app.env")
	fake := fakeGitleaksBinary(t, `[{"RuleID":"generic-api-key","File":"app.env","StartLine":1,"Secret":"abc123-secret-value","Match":"API_KEY=abc123-secret-value"}]`)

	code, stdout, stderr := run(t, []string{"secrets", "scans", "staged-diff", "--repo", repo, "--gitleaks-bin", fake}, cli.Env{}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when findings are present; stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{`"capability": "CAP-SCAN-02"`, `"mode": "staged"`, `"files_scanned": 1`, `"findings_count": 1`, `"credential_ref": "generic-api-key@app.env"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "abc123-secret-value") || strings.Contains(stderr, "abc123-secret-value") {
		t.Fatalf("staged-diff leaked raw secret value:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "secret finding") {
		t.Fatalf("stderr = %q, want finding failure summary", stderr)
	}
}

func TestSecretScanStagedDiffSupportsCIDiffMode(t *testing.T) {
	repo := initCLIGitRepo(t)
	writeCLIGitFile(t, repo, "README.md", "base\n")
	gitCLI(t, repo, "add", "README.md")
	gitCLI(t, repo, "commit", "-m", "base")
	base := strings.TrimSpace(gitCLIOutput(t, repo, "rev-parse", "HEAD"))
	writeCLIGitFile(t, repo, "ci.env", "CI_TOKEN=abc123-secret-value\n")
	gitCLI(t, repo, "add", "ci.env")
	gitCLI(t, repo, "commit", "-m", "head")
	head := strings.TrimSpace(gitCLIOutput(t, repo, "rev-parse", "HEAD"))
	fake := fakeGitleaksBinary(t, `[{"RuleID":"generic-api-key","File":"ci.env","StartLine":1,"Secret":"abc123-secret-value"}]`)

	code, stdout, stderr := run(t, []string{"secrets", "scans", "staged-diff", "--repo", repo, "--base", base, "--head", head, "--gitleaks-bin", fake, "--advisory"}, cli.Env{}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr)
	}
	for _, want := range []string{`"capability": "CAP-SCAN-02"`, `"mode": "ci_diff"`, `"files": [`, `"ci.env"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "abc123-secret-value") || strings.Contains(stderr, "abc123-secret-value") {
		t.Fatalf("CI diff scan leaked raw secret value:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

func TestSecretScanPreCommitInstallWritesHook(t *testing.T) {
	repo := initCLIGitRepo(t)
	fake := fakeGitleaksBinary(t, `[]`)

	code, stdout, stderr := run(t, []string{"secrets", "scans", "pre-commit", "install", "--repo", repo, "--gitleaks-bin", fake}, cli.Env{}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr)
	}
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("hook mode = %v, want executable", info.Mode())
	}
	hook := string(data)
	for _, want := range []string{"secrets scans staged-diff", "--repo", repo, "--gitleaks-bin", fake} {
		if !strings.Contains(hook, want) {
			t.Errorf("hook missing %q:\n%s", want, hook)
		}
	}
	for _, want := range []string{`"capability": "CAP-SCAN-02"`, `"installed": true`, `"hook_path":`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
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

func TestNotificationCommandsSendPathsQueriesAndIdempotencyKeys(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"items":[]}`, &cap)
	env := cli.Env{Server: srv.URL, HTTPClient: srv.Client(), IdempotencyKey: "notif-cli-idem"}

	code, _, _ := run(t, []string{"notifications", "channels"}, env, "")
	if code != 0 {
		t.Fatalf("channels exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-channels" {
		t.Errorf("channels request = %s %s", cap.Method, cap.Path)
	}

	channelBody := `{"id":"webhook","channel_type":"webhook","label":"Tenant webhook","endpoint_url":"https://hooks.example.test/trstctl","credential_ref":"secret://notifications/webhook/hmac-key","enabled":true}`
	code, _, _ = run(t, []string{"notifications", "channels", "create", "-f", "-"}, env, channelBody)
	if code != 0 {
		t.Fatalf("channel create exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notification-channels" {
		t.Errorf("channel create request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != channelBody {
		t.Errorf("channel create body = %q, want %q", cap.Body, channelBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel create Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "channels", "get", "webhook"}, env, "")
	if code != 0 {
		t.Fatalf("channel get exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-channels/webhook" {
		t.Errorf("channel get request = %s %s", cap.Method, cap.Path)
	}

	code, _, _ = run(t, []string{"notifications", "channels", "update", "webhook", "-f", "-"}, env, channelBody)
	if code != 0 {
		t.Fatalf("channel update exit = %d", code)
	}
	if cap.Method != "PUT" || cap.Path != "/api/v1/notification-channels/webhook" {
		t.Errorf("channel update request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != channelBody {
		t.Errorf("channel update body = %q, want %q", cap.Body, channelBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel update Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "channels", "delete", "webhook", "--force"}, env, "")
	if code != 0 {
		t.Fatalf("channel delete exit = %d", code)
	}
	if cap.Method != "DELETE" || cap.Path != "/api/v1/notification-channels/webhook" {
		t.Errorf("channel delete request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel delete Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	testBody := `{"severity":"critical","credential_ref":"secret://notifications/slack/raw-webhook-url"}`
	code, _, _ = run(t, []string{"notifications", "channels", "test", "slack", "-f", "-"}, env, testBody)
	if code != 0 {
		t.Fatalf("channel test exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notification-channels/slack/test" {
		t.Errorf("channel test request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != testBody {
		t.Errorf("channel test body = %q, want %q", cap.Body, testBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel test Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	policyBody := `{"name":"Expiry escalation","default_channels":["slack"],"channels_by_severity":{"critical":["slack"]}}`
	code, _, _ = run(t, []string{"notifications", "routing-policies", "create", "-f", "-"}, env, policyBody)
	if code != 0 {
		t.Fatalf("routing policy create exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notification-routing-policies" {
		t.Errorf("routing policy create request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != policyBody {
		t.Errorf("routing policy create body = %q, want %q", cap.Body, policyBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("routing policy create Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "routing-policies", "list"}, env, "")
	if code != 0 {
		t.Fatalf("routing policy list exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-routing-policies" {
		t.Errorf("routing policy list request = %s %s", cap.Method, cap.Path)
	}

	const policyID = "11111111-1111-4111-8111-111111111111"
	code, _, _ = run(t, []string{"notifications", "routing-policies", "get", policyID}, env, "")
	if code != 0 {
		t.Fatalf("routing policy get exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-routing-policies/"+policyID {
		t.Errorf("routing policy get request = %s %s", cap.Method, cap.Path)
	}

	code, _, _ = run(t, []string{"notifications", "routing-policies", "update", policyID, "-f", "-"}, env, policyBody)
	if code != 0 {
		t.Fatalf("routing policy update exit = %d", code)
	}
	if cap.Method != "PUT" || cap.Path != "/api/v1/notification-routing-policies/"+policyID {
		t.Errorf("routing policy update request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != policyBody {
		t.Errorf("routing policy update body = %q, want %q", cap.Body, policyBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("routing policy update Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "routing-policies", "delete", policyID, "--force"}, env, "")
	if code != 0 {
		t.Fatalf("routing policy delete exit = %d", code)
	}
	if cap.Method != "DELETE" || cap.Path != "/api/v1/notification-routing-policies/"+policyID {
		t.Errorf("routing policy delete request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("routing policy delete Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "list", "--status", "dead", "--limit", "10"}, env, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notifications" {
		t.Errorf("list request = %s %s", cap.Method, cap.Path)
	}
	if !strings.Contains(cap.Query, "status=dead") || !strings.Contains(cap.Query, "limit=10") {
		t.Errorf("list query = %q, want status and limit", cap.Query)
	}

	code, _, _ = run(t, []string{"notifications", "get", "42"}, env, "")
	if code != 0 {
		t.Fatalf("get exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notifications/42" {
		t.Errorf("get request = %s %s", cap.Method, cap.Path)
	}

	code, _, _ = run(t, []string{"notifications", "read", "42"}, env, "")
	if code != 0 {
		t.Fatalf("read exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notifications/42/read" {
		t.Errorf("read request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("read Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "requeue", "42"}, env, "")
	if code != 0 {
		t.Fatalf("requeue exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notifications/42/requeue" {
		t.Errorf("requeue request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("requeue Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
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

func initCLIGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitCLI(t, repo, "init")
	gitCLI(t, repo, "config", "user.email", "test@example.com")
	gitCLI(t, repo, "config", "user.name", "trstctl test")
	return repo
}

func writeCLIGitFile(t *testing.T, repo, name, body string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gitCLI(t *testing.T, repo string, args ...string) {
	t.Helper()
	_ = gitCLIOutput(t, repo, args...)
}

func gitCLIOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func fakeGitleaksBinary(t *testing.T, reportJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gitleaks")
	script := `#!/bin/sh
set -eu
report=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then
    shift
    report="$1"
  fi
  shift || true
done
if [ -z "$report" ]; then
  echo "missing --report-path" >&2
  exit 2
fi
cat > "$report" <<'JSON'
` + reportJSON + `
JSON
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
