package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
