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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// P7 Done when (host detectors): a test host with two assistants configured
// shows each MCP server they use, with static tokens flagged and no value
// stored; a rescan with no changes writes no new events. The shipped
// collector reads the host, the agent reports over the mTLS channel, and the
// servers appear in discovery and in the shadow NHI posture.
func TestServedMCPClientInventoryP7(t *testing.T) {
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
	a := enrollAgent(t, h, "edge-agent-mcp", "agent.trstctl.local")
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

	// Two assistants on the test host: one desktop configuration, one IDE
	// workspace file, each with servers holding static tokens beside servers
	// that reference theirs.
	secrets := []string{"tkn_1234567890abcdefghijklmnop", "abc123secretquery", "xyzheadervalue", "hunter2hunter2"}
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
	write("assistant-a/config.json", `{"mcpServers": {
  "files": {"command": "npx", "args": ["-y", "files-server", "/srv/shared"]},
  "tracker": {"command": "tracker-mcp", "env": {"TRACKER_TOKEN": "tkn_1234567890abcdefghijklmnop"}},
  "remote": {"url": "https://mcp.example.test/sse?api_key=abc123secretquery", "headers": {"Authorization": "Bearer xyzheadervalue"}}}}`)
	write("workspace/.ide/mcp.json", `{
  // this workspace's servers
  "servers": {
    "db": {"type": "stdio", "command": "db-mcp", "args": ["--password", "hunter2hunter2"]},
    "docs": {"type": "http", "url": "https://docs.example.test/mcp", "headers": {"Authorization": "${input:docs-token}"}},
  },
}`)
	state := filepath.Join(t.TempDir(), "mcp-inventory.digest")
	tenantEvents := func() (int, []events.Event) {
		t.Helper()
		n, all := 0, []events.Event{}
		if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
			if e.TenantID == h.tenant {
				n++
				all = append(all, e)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n, all
	}

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
			Kind     string            `json:"kind"`
			Metadata map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	flagged := map[string]string{}
	for _, item := range list.Items {
		if !strings.HasPrefix(item.Ref, root) {
			continue
		}
		name := item.Metadata["server_name"]
		if item.Metadata["host"] != "edge-agent-mcp" {
			t.Fatalf("%s names host %q", name, item.Metadata["host"])
		}
		if item.Metadata["static_credential"] == "true" {
			flagged[name] = item.Metadata["credential_fields"]
		}
	}
	want := map[string]string{"tracker": "env:TRACKER_TOKEN", "remote": "header:Authorization,url:query:api_key", "db": "arg:--password"}
	if len(flagged) != len(want) {
		t.Fatalf("flagged = %v, want %v (%s)", flagged, want, body)
	}
	for name, fields := range want {
		if flagged[name] != fields {
			t.Fatalf("%s flagged %q, want %q", name, flagged[name], fields)
		}
	}
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/shadow", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("shadow posture: %d %s", code, body)
	}
	var shadow struct {
		Summary struct {
			KindCounts map[string]int `json:"kind_counts"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &shadow); err != nil {
		t.Fatal(err)
	}
	if shadow.Summary.KindCounts[discovery.FindingKindMCPServer] < 5 {
		t.Fatalf("shadow posture kind counts = %v", shadow.Summary.KindCounts)
	}

	// No value stored: not in any event, read model row or API answer.
	_, all := tenantEvents()
	var findingRows string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(string_agg(ref || ' ' || provenance || ' ' || fingerprint || ' ' || metadata::text, ' '), '')
			FROM discovery_findings WHERE tenant_id = $1 AND kind = $2`, h.tenant, discovery.FindingKindMCPServer).Scan(&findingRows)
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		for _, e := range all {
			if strings.Contains(string(e.Data), s) {
				t.Fatalf("event %s %s holds a credential value", e.Type, e.ID)
			}
		}
		if strings.Contains(string(findingRows), s) || strings.Contains(string(body), s) {
			t.Fatalf("a credential value reached the inventory: %q", s)
		}
	}

	// A rescan with no changes sends nothing and writes no event.
	before, _ := tenantEvents()
	if resp, sent, err := a.ReportMCPInventory(ctx, channelClientAdapter{c: client}, []string{root}, state); err != nil || sent || resp != nil {
		t.Fatalf("unchanged rescan = %+v sent=%v err=%v", resp, sent, err)
	}
	if after, _ := tenantEvents(); after != before {
		t.Fatalf("an unchanged rescan wrote %d events", after-before)
	}
	// A new server is reported.
	write("assistant-b/config.json", `{"mcpServers": {"notes": {"command": "notes-mcp"}}}`)
	if resp, sent, err := a.ReportMCPInventory(ctx, channelClientAdapter{c: client}, []string{root}, state); err != nil || !sent || resp.Recorded != 6 {
		t.Fatalf("changed rescan = %+v sent=%v err=%v", resp, sent, err)
	}

	// The control plane keeps the report to its closed shape: a credential
	// value, an unknown metadata key or a URL with a path is refused whole.
	for _, bad := range []map[string]string{
		{"server_name": "x", "credential_values": "tkn_1234567890abcdefghijklmnop"},
		{"server_name": "x", "token_hint": "abc"},
		{"server_name": "x", "url_host": "https://mcp.example.test/sse?api_key=abc123secretquery"},
		{"server_name": "x", "credential_fields": "env:A=B"},
	} {
		_, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: discovery.SourceMCPClientConfig,
			Findings: []transport.InventoryFinding{{Kind: discovery.FindingKindMCPServer, Ref: root + "/bad#x", Metadata: bad}}})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("report with %v = %v, want InvalidArgument", bad, err)
		}
	}
	if _, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem",
		Findings: []transport.InventoryFinding{{Kind: discovery.FindingKindMCPServer, Ref: root + "/bad#y"}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an MCP server finding from another source = %v, want InvalidArgument", err)
	}
}
