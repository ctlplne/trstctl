// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secretscan/validity"
)

// P14-L2: an agent checks the static tokens it finds in MCP client
// configuration from its own host, and only the verdict reaches the control
// plane: a live GitHub token and a live GitLab token are valid, a revoked
// Slack token invalid, a password no provider checks carries no verdict, and
// no value is in any event, read-model row or API answer. A rescan with
// nothing changed sends nothing; once the GitHub token is revoked the next
// scan reports it invalid. The control plane holds verdicts to their closed
// shape.
func TestServedMCPStaticTokensAreCheckedOnTheAgentP14L2(t *testing.T) {
	github := "ghp_" + "P14L2servedGitHubToken00000000000001"
	slack := "xoxb-" + "1414-1414-P14L2servedSlackBot"
	gitlab := "glpat-" + "P14L2servedGitLab000"
	var mu sync.Mutex
	githubRevoked := false
	var calls []string
	identity := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		revoked := githubRevoked
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user" && bearer == github && !revoked:
			_ = json.NewEncoder(w).Encode(map[string]any{"login": "p14l2-dev"})
		case r.URL.Path == "/user":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
		case r.URL.Path == "/api/v4/personal_access_tokens/self" && r.Header.Get("PRIVATE-TOKEN") == gitlab:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 9, "name": "repo-mcp", "user_id": 42, "active": true, "scopes": []string{"read_api"}})
		case r.URL.Path == "/api/auth.test":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "token_revoked"})
		default:
			t.Errorf("unexpected identity call: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	t.Cleanup(identity.Close)
	checker := validity.New(validity.Config{Providers: []string{validity.ProviderGitHub, validity.ProviderGitLab, validity.ProviderSlack},
		Endpoints: map[string]string{validity.ProviderGitHub: identity.URL, validity.ProviderGitLab: identity.URL, validity.ProviderSlack: identity.URL},
		Allowlist: []string{identity.URL}, Client: identity.Client(),
		Rates: map[string]float64{validity.ProviderGitHub: 50, validity.ProviderGitLab: 50, validity.ProviderSlack: 50}})

	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a := enrollAgent(t, h, "edge-agent-p14l2", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	registerInventoryAgent(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	root := t.TempDir()
	mcpConfig := `{"mcpServers": {
  "code": {"command": "code-mcp", "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "` + github + `"}},
  "chat": {"url": "https://chat.example.test/mcp", "headers": {"Authorization": "Bearer ` + slack + `"}},
  "repo": {"command": "repo-mcp", "args": ["--token=` + gitlab + `"]},
  "db": {"command": "db-mcp", "args": ["--password", "hunter2hunter2"]}}}`
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(mcpConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "mcp-inventory.digest")
	report := func() (*int, bool) {
		t.Helper()
		resp, sent, err := a.ReportMCPInventory(ctx, channelClientAdapter{c: client}, []string{root}, state, checker)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			return nil, sent
		}
		n := resp.Recorded
		if resp.Rejected != 0 {
			t.Fatalf("report rejected %d findings", resp.Rejected)
		}
		return &n, sent
	}
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	verdicts := func() map[string]map[string]string {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind="+discovery.FindingKindMCPServer+"&limit=100", tok, nil)
		if code != http.StatusOK {
			t.Fatalf("findings: %d %s", code, body)
		}
		for _, value := range []string{github, slack, gitlab, "hunter2hunter2"} {
			if strings.Contains(string(body), value) {
				t.Fatal("the findings API carries a credential value")
			}
		}
		var list struct {
			Items []struct {
				Ref      string            `json:"ref"`
				Metadata map[string]string `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]map[string]string{}
		for _, item := range list.Items {
			if strings.HasPrefix(item.Ref, root) {
				out[item.Metadata["server_name"]] = item.Metadata
			}
		}
		return out
	}

	if n, sent := report(); !sent || n == nil || *n != 4 {
		t.Fatalf("first report sent=%v recorded=%v", sent, n)
	}
	got := verdicts()
	for name, want := range map[string]string{"code": "env:GITHUB_PERSONAL_ACCESS_TOKEN=github:valid", "chat": "header:Authorization=slack:invalid",
		"repo": "arg:--token=gitlab:valid", "db": ""} {
		if got[name]["credential_validity"] != want {
			t.Fatalf("%s's verdict = %q, want %q (%v)", name, got[name]["credential_validity"], want, got[name])
		}
	}
	if !strings.Contains(got["code"]["credential_validity_detail"], "user p14l2-dev") ||
		!strings.Contains(got["chat"]["credential_validity_detail"], "token_revoked") || got["code"]["host"] != "edge-agent-p14l2" {
		t.Fatalf("details = %v / %v", got["code"], got["chat"])
	}
	mu.Lock()
	checks := len(calls)
	mu.Unlock()
	if checks != 3 {
		t.Fatalf("the agent made %d identity calls, want one per token", checks)
	}

	// No value stored: not in any event or read-model row.
	var all []events.Event
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID == h.tenant {
			all = append(all, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var rows string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(string_agg(metadata::text, ' '), '') FROM discovery_findings WHERE tenant_id = $1 AND kind = $2`,
			h.tenant, discovery.FindingKindMCPServer).Scan(&rows)
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{github, slack, gitlab, "hunter2hunter2"} {
		if strings.Contains(rows, value) {
			t.Fatal("a read-model row carries a credential value")
		}
		for _, e := range all {
			if strings.Contains(string(e.Data), value) {
				t.Fatalf("event %s carries a credential value", e.Type)
			}
		}
	}

	// Nothing changed: nothing is sent. The GitHub token revoked: reported again.
	if _, sent := report(); sent {
		t.Fatal("an unchanged rescan sent a report")
	}
	mu.Lock()
	githubRevoked = true
	mu.Unlock()
	if n, sent := report(); !sent || n == nil || *n != 4 {
		t.Fatalf("the rescan after a revocation sent=%v recorded=%v", sent, n)
	}
	if v := verdicts()["code"]["credential_validity"]; v != "env:GITHUB_PERSONAL_ACCESS_TOKEN=github:invalid" {
		t.Fatalf("the revoked token's verdict = %q", v)
	}

	// The closed shape: a verdict for a field the finding does not report, an
	// unknown provider or state, or a detail with no verdict is refused whole.
	for _, bad := range []map[string]string{
		{"server_name": "x", "credential_fields": "env:A", "credential_validity": "env:B=github:valid"},   // #nosec G101 -- closed-shape test metadata naming fields and verdicts, no credential (CWE-798)
		{"server_name": "x", "credential_fields": "env:A", "credential_validity": "env:A=aws:valid"},      // #nosec G101 -- closed-shape test metadata naming fields and verdicts, no credential (CWE-798)
		{"server_name": "x", "credential_fields": "env:A", "credential_validity": "env:A=github:live"},    // #nosec G101 -- closed-shape test metadata naming fields and verdicts, no credential (CWE-798)
		{"server_name": "x", "credential_fields": "env:A", "credential_validity_detail": "env:A: user x"}, // #nosec G101 -- closed-shape test metadata naming fields and verdicts, no credential (CWE-798)
	} {
		_, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: discovery.SourceMCPClientConfig,
			Findings: []transport.InventoryFinding{{Kind: discovery.FindingKindMCPServer, Ref: root + "/bad#x", Metadata: bad}}})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("report with %v = %v, want InvalidArgument", bad, err)
		}
	}
	t.Logf("P14L2_AGENT_CHECKS_OK servers=4 checks=%d", checks)
}
