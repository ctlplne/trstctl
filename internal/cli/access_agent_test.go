// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

const (
	agentTestToken  = "trst_agent-run-token-value" // #nosec G101 -- a fake run token the test's fake control plane expects (CWE-798)
	agentTestTicket = "gw-ticket-value-never-shown"
	agentTestReview = "8a3c0000-0000-4000-8000-0000000000a1"
	agentTestID     = "8a3c0000-0000-4000-8000-0000000000b2"
)

// accessAgentServer answers the launcher's calls: a reviewed request, its
// approval after one pending read, the open, and the revoke.
type accessAgentServer struct {
	mu       sync.Mutex
	calls    []string
	request  map[string]any
	open     map[string]any
	reads    int
	delivery string
	refuse   bool
}

func (s *accessAgentServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer "+agentTestToken {
			t.Errorf("%s %s sent %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/access/session-requests":
			if s.refuse {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"title":"Forbidden","detail":"ssh/ssh-gw as user is not among the accounts this run's access bundles delegate"}`)
				return
			}
			if err := json.Unmarshal(body, &s.request); err != nil {
				t.Errorf("request body: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"approval_request_id":"`+agentTestReview+`","intent_digest":"digest-1","status":"pending","required_approvals":2}`)
		case "GET /api/v1/access/session-requests/" + agentTestReview:
			s.reads++
			status := "pending"
			if s.reads > 1 {
				status = "approved"
			}
			_, _ = io.WriteString(w, `{"status":"`+status+`"}`)
		case "POST /api/v1/access/sessions":
			if err := json.Unmarshal(body, &s.open); err != nil {
				t.Errorf("open body: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			if s.delivery == "direct" {
				_, _ = io.WriteString(w, `{"id":"`+agentTestID+`","expires_at":"2026-11-04T23:00:00Z","delivery":"direct","postgres":{"dsn":"postgres://u:direct-password@db/x"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"id":"`+agentTestID+`","expires_at":"2026-11-04T23:00:00Z","delivery":"gateway",`+
				`"gateway":{"address":"127.0.0.1:9","spiffe_id":"spiffe://t/agent/gw","ca_pem":"pem","ticket":"`+agentTestTicket+`"}}`)
		case "POST /api/v1/access/sessions/" + agentTestID + "/revoke":
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"id":"`+agentTestID+`","status":"revoking"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"title":"not found"}`)
		}
	}
}

// A257: `access agent` requests a reviewed session for each account, waits
// for its approval, opens it through the gateway and runs the command with a
// loopback tunnel and instructions: the command's environment holds no
// control-plane token and no ticket, nothing printed holds either, and the
// session is revoked when the command exits.
func TestAccessAgentRunsTheCommandWithTunnelsAndNoCredential(t *testing.T) {
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	t.Setenv("TRSTCTL_TOKEN", agentTestToken)
	t.Setenv("TRSTCTL_ADMIN_TOKEN", "another-control-plane-token")
	s := &accessAgentServer{}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	dir := t.TempDir()
	payload := filepath.Join(dir, "attestation")
	if err := os.WriteFile(payload, []byte("genuine"), 0o600); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "env.txt")
	code, stdout, stderr := run(t, []string{"access", "agent", "--account", "postgres/pg-gw:readonly", "--reason", "nightly report",
		"--method", "stub_pam", "--payload-file", payload, "--ttl", "5m", "--",
		shPath, "-c", `env > "$0"; cat "$TRSTCTL_ACCESS_INSTRUCTIONS"`, envFile},
		cli.Env{Server: srv.URL, Token: agentTestToken, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d; stderr=%s", code, stderr)
	}
	if s.request["target_type"] != "postgres" || s.request["target_id"] != "pg-gw" || s.request["role"] != "readonly" ||
		s.request["reason"] != "nightly report" || s.request["method"] != "stub_pam" || s.request["payload_base64"] != "Z2VudWluZQ==" ||
		s.request["ttl_seconds"] != float64(300) || s.request["request_id"] == "" {
		t.Fatalf("session request = %v", s.request)
	}
	if s.open["approval_request_id"] != agentTestReview || s.open["intent_digest"] != "digest-1" || s.open["request_id"] != s.request["request_id"] {
		t.Fatalf("open = %v", s.open)
	}
	if s.reads < 2 {
		t.Fatalf("the launcher opened before the approval: %d progress reads", s.reads)
	}
	envText, err := os.ReadFile(envFile) // #nosec G304 -- the file the test's own child wrote in the test's temp dir (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{agentTestToken, agentTestTicket, "another-control-plane-token", "TRSTCTL_TOKEN=", "TRSTCTL_ADMIN_TOKEN="} {
		for name, text := range map[string]string{"environment": string(envText), "stdout": stdout, "stderr": stderr} {
			if strings.Contains(text, leaked) {
				t.Fatalf("the command's %s holds %q", name, leaked)
			}
		}
	}
	for _, want := range []string{"TRSTCTL_ACCESS_1_TYPE=postgres", "TRSTCTL_ACCESS_1_TARGET=pg-gw", "TRSTCTL_ACCESS_1_ROLE=readonly",
		"TRSTCTL_ACCESS_1_ADDR=127.0.0.1:", "PGHOST=127.0.0.1", "PGPORT=", "PGSSLMODE=disable", "TRSTCTL_ACCESS_INSTRUCTIONS="} {
		if !strings.Contains(string(envText), want) {
			t.Fatalf("the command's environment lacks %s:\n%s", want, envText)
		}
	}
	if !strings.Contains(stdout, "You hold no credential") || !strings.Contains(stdout, "postgres pg-gw as readonly") ||
		!strings.Contains(stdout, `psql "host=127.0.0.1 port=`) {
		t.Fatalf("instructions = %s", stdout)
	}
	if last := s.calls[len(s.calls)-1]; last != "POST /api/v1/access/sessions/"+agentTestID+"/revoke" || !strings.Contains(stderr, "session "+agentTestID+" revoked") {
		t.Fatalf("the session was not revoked at exit: calls=%v stderr=%s", s.calls, stderr)
	}
}

// A257: an account outside the run's delegated accounts is refused before
// anything runs, and a session delivered with its credential instead of
// through a gateway is revoked at once without running the command.
func TestAccessAgentRefusesUndelegatedAndDirectAccounts(t *testing.T) {
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "attestation")
	if err := os.WriteFile(payload, []byte("genuine"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := filepath.Join(dir, "ran")
	args := func(account string) []string {
		return []string{"access", "agent", "--account", account, "--reason", "r", "--method", "stub_pam", "--payload-file", payload,
			"--", shPath, "-c", `touch "$0"`, ran}
	}

	refused := &accessAgentServer{refuse: true}
	srv := httptest.NewServer(refused.handler(t))
	code, _, stderr := run(t, args("ssh/ssh-gw:user"), cli.Env{Server: srv.URL, Token: agentTestToken, HTTPClient: srv.Client()}, "")
	srv.Close()
	if code != 1 || !strings.Contains(stderr, "not among the accounts this run's access bundles delegate") {
		t.Fatalf("undelegated account: exit %d, stderr=%s", code, stderr)
	}

	direct := &accessAgentServer{delivery: "direct"}
	srv = httptest.NewServer(direct.handler(t))
	code, stdout, stderr := run(t, args("postgres/pg-direct:readonly"), cli.Env{Server: srv.URL, Token: agentTestToken, HTTPClient: srv.Client()}, "")
	srv.Close()
	if code != 1 || !strings.Contains(stderr, "not delivered through a gateway") || strings.Contains(stdout+stderr, "direct-password") {
		t.Fatalf("direct account: exit %d, stdout=%s stderr=%s", code, stdout, stderr)
	}
	if last := direct.calls[len(direct.calls)-1]; last != "POST /api/v1/access/sessions/"+agentTestID+"/revoke" {
		t.Fatalf("the direct session was not revoked: %v", direct.calls)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the command ran without its accounts")
	}

	if code, _, _ := run(t, []string{"access", "agent", "--account", "postgres", "--reason", "r", "--method", "m", "--payload-file", payload, "--", shPath},
		cli.Env{Server: "http://127.0.0.1:1", Token: agentTestToken}, ""); code != 2 {
		t.Fatalf("a malformed --account exit = %d, want 2", code)
	}
}
