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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
)

// P7-L2: an MCP client configuration removed from a host is reported gone.
// Each report is the host's whole inventory, so a server the newest report
// no longer lists reads removed_at and leaves the open shadow NHI posture; a
// host whose last configuration is removed sends one empty report, and a
// server configured again reads present. Other sources still refuse an
// empty report.
func TestServedMCPClientInventoryReportsARemovedServerP7L2(t *testing.T) {
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
	a := enrollAgent(t, h, "edge-agent-mcp-removed", "agent.trstctl.local")
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
	desktop := filepath.Join(root, "assistant-a", "config.json")
	workspace := filepath.Join(root, "workspace", ".ide", "mcp.json")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const desktopBody = `{"mcpServers": {"files": {"command": "files-mcp"}, "tracker": {"command": "tracker-mcp"}}}`
	const workspaceBody = `{"servers": {"db": {"type": "stdio", "command": "db-mcp"}}}`
	write(desktop, desktopBody)
	write(workspace, workspaceBody)
	state := filepath.Join(t.TempDir(), "mcp-inventory.digest")
	report := func(wantSent bool, wantRecorded int) {
		t.Helper()
		resp, sent, err := a.ReportMCPInventory(ctx, channelClientAdapter{c: client}, []string{root}, state)
		if err != nil || sent != wantSent || (sent && resp.Recorded != wantRecorded) {
			t.Fatalf("report = %+v sent=%v err=%v, want sent=%v recorded=%d", resp, sent, err, wantSent, wantRecorded)
		}
	}
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "nhi:read")
	// servers maps each of this host's servers to whether it reads removed,
	// and its finding ID.
	servers := func() (map[string]bool, map[string]string) {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind="+discovery.FindingKindMCPServer+"&limit=100", tok, nil)
		if code != http.StatusOK {
			t.Fatalf("findings: %d %s", code, body)
		}
		var list struct {
			Items []struct {
				ID        string            `json:"id"`
				Ref       string            `json:"ref"`
				Metadata  map[string]string `json:"metadata"`
				RemovedAt *time.Time        `json:"removed_at"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		removed, ids := map[string]bool{}, map[string]string{}
		for _, item := range list.Items {
			if !strings.HasPrefix(item.Ref, root) {
				continue
			}
			name := item.Metadata["server_name"]
			removed[name] = item.RemovedAt != nil
			ids[name] = item.ID
		}
		return removed, ids
	}
	// posture lists which of this host's findings are in the open shadow
	// posture, and the posture's removed count.
	posture := func(ids map[string]string) (map[string]bool, int) {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/shadow", tok, nil)
		if code != http.StatusOK {
			t.Fatalf("shadow posture: %d %s", code, body)
		}
		var shadow struct {
			Summary struct {
				Removed int `json:"removed"`
			} `json:"summary"`
			Findings []struct {
				FindingID string `json:"finding_id"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(body, &shadow); err != nil {
			t.Fatal(err)
		}
		open := map[string]bool{}
		for name, id := range ids {
			for _, f := range shadow.Findings {
				if f.FindingID == id {
					open[name] = true
				}
			}
		}
		return open, shadow.Summary.Removed
	}
	check := func(when string, wantRemoved map[string]bool) {
		t.Helper()
		removed, ids := servers()
		if len(removed) != len(wantRemoved) {
			t.Fatalf("%s: servers %v, want %v", when, removed, wantRemoved)
		}
		gone := 0
		for name, want := range wantRemoved {
			if removed[name] != want {
				t.Fatalf("%s: %s removed=%v, want %v (all: %v)", when, name, removed[name], want, removed)
			}
			if want {
				gone++
			}
		}
		open, removedCount := posture(ids)
		for name, want := range wantRemoved {
			if open[name] == want {
				t.Fatalf("%s: %s in the open posture = %v, want %v", when, name, open[name], !want)
			}
		}
		if removedCount < gone {
			t.Fatalf("%s: the posture counts %d removed, want at least %d", when, removedCount, gone)
		}
	}

	report(true, 3)
	check("all configured", map[string]bool{"files": false, "tracker": false, "db": false})

	// The workspace file is deleted: its server is gone, the others stay.
	if err := os.Remove(workspace); err != nil {
		t.Fatal(err)
	}
	report(true, 2)
	check("workspace removed", map[string]bool{"files": false, "tracker": false, "db": true})

	// The last configuration goes: one empty report says so, once.
	if err := os.Remove(desktop); err != nil {
		t.Fatal(err)
	}
	report(true, 0)
	check("everything removed", map[string]bool{"files": true, "tracker": true, "db": true})
	report(false, 0)

	// A server configured again reads present.
	write(workspace, workspaceBody)
	report(true, 1)
	check("workspace back", map[string]bool{"files": true, "tracker": true, "db": false})

	// Only the MCP client configuration source is a whole inventory; any
	// other source still needs a finding.
	if _, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty filesystem report = %v, want InvalidArgument", err)
	}
}
