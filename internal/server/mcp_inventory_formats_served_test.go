// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// Fixture values only, spliced in so no scanner reads a credential-shaped
// literal in this file.
var (
	p7l1ServedFakeTracker = "tkn_" + "1234567890abcdefghijklmnop"
	p7l1ServedFakeGitHub  = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123"
	p7l1ServedFakeGitLab  = "glpat-" + "abcdefghij0123456789"
)

// P7-L1: MCP servers configured in TOML and YAML on a test host reach the
// control plane over the real agent channel like JSON's: each server with its
// format, transport and program or host, static credentials named by field,
// no value in any event or row, and an unchanged rescan sends nothing.
func TestServedMCPClientInventoryFromTOMLAndYAMLP7L1(t *testing.T) {
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
	a := enrollAgent(t, h, "edge-agent-mcp-formats", "agent.trstctl.local")
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secrets := []string{p7l1ServedFakeTracker, p7l1ServedFakeGitHub, p7l1ServedFakeGitLab}
	root := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("cli-assistant/config.toml", `[mcp_servers.files]
command = "npx"
args = ["-y", "files-server", "/srv/shared"]

[mcp_servers.tracker]
command = "tracker-mcp"
env = { TRACKER_TOKEN = "`+p7l1ServedFakeTracker+`" }
`)
	write("assistant/config.yaml", `mcpServers:
  git:
    command: git-mcp
    env:
      API_KEY: "`+p7l1ServedFakeGitHub+`"
  docs:
    type: http
    url: https://docs.example.test/mcp
`)
	write("ide/servers.yml", `servers:
- name: ci
  command: ci-mcp
  args: [--token, "`+p7l1ServedFakeGitLab+`"]
`)
	state := filepath.Join(t.TempDir(), "mcp-inventory.digest")
	resp, sent, err := a.ReportMCPInventory(ctx, channelClientAdapter{c: client}, []string{root}, state)
	if err != nil || !sent || resp.Recorded != 5 || resp.Rejected != 0 {
		t.Fatalf("first report = %+v sent=%v err=%v", resp, sent, err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "nhi:read")
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind="+discovery.FindingKindMCPServer+"&limit=100", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("findings: %d %s", code, body)
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
	got := map[string]string{}
	for _, item := range list.Items {
		if !strings.HasPrefix(item.Ref, root) {
			continue
		}
		m := item.Metadata
		got[m["server_name"]] = m["format"] + "|" + m["transport"] + "|" + m["command"] + m["url_host"] + "|" + m["credential_fields"]
	}
	want := map[string]string{
		"files":   "mcp_servers|stdio|npx|",
		"tracker": "mcp_servers|stdio|tracker-mcp|env:TRACKER_TOKEN",
		"git":     "mcpServers|stdio|git-mcp|env:API_KEY",
		"docs":    "mcpServers|http|https://docs.example.test|",
		"ci":      "servers|stdio|ci-mcp|arg:--token",
	}
	if len(got) != len(want) {
		t.Fatalf("servers = %v, want %v", got, want)
	}
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("%s = %q, want %q", name, got[name], w)
		}
	}

	// No value stored: not in any event or read-model row.
	var findingRows string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(string_agg(ref || ' ' || provenance || ' ' || fingerprint || ' ' || metadata::text, ' '), '')
			FROM discovery_findings WHERE tenant_id = $1 AND kind = $2`, h.tenant, discovery.FindingKindMCPServer).Scan(&findingRows)
	}); err != nil {
		t.Fatal(err)
	}
	eventCount := 0
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID != h.tenant {
			return nil
		}
		eventCount++
		for _, s := range secrets {
			if strings.Contains(string(e.Data), s) {
				t.Fatalf("event %s %s holds a credential value", e.Type, e.ID)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(findingRows, s) || strings.Contains(string(body), s) {
			t.Fatalf("a credential value reached the inventory: %q", s)
		}
	}
	if resp, sent, err := a.ReportMCPInventory(ctx, channelClientAdapter{c: client}, []string{root}, state); err != nil || sent || resp != nil {
		t.Fatalf("unchanged rescan = %+v sent=%v err=%v", resp, sent, err)
	}
	t.Logf("P7L1_FORMATS_OK servers=%d events=%d", len(got), eventCount)
}
