// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The values a test host's configurations hold; none may appear in anything
// the source returns or the agent reports.
var mcpTestSecrets = []string{"tkn_1234567890abcdefghijklmnop", "abc123secretquery", "Bearer xyzheadervalue", "hunter2hunter2",
	"ghp_abcdefghijklmnopqrstuvwxyz0123", "s3cr3t-userinfo"}

func writeMCPTestHost(t *testing.T) string {
	t.Helper()
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
	// A desktop assistant's configuration: an mcpServers object.
	write("assistant-a/config.json", `{
  "theme": "dark",
  "mcpServers": {
    "files": {"command": "/usr/local/bin/npx", "args": ["-y", "files-server", "/srv/shared"]},
    "tracker": {"command": "tracker-mcp", "env": {"TRACKER_TOKEN": "tkn_1234567890abcdefghijklmnop", "GIT_AUTHOR_NAME": "Build Bot"}},
    "remote": {"url": "https://mcp.example.test:8443/sse?api_key=abc123secretquery&region=eu",
               "headers": {"Authorization": "Bearer xyzheadervalue", "Accept": "text/event-stream"}}
  }
}`)
	// An IDE's workspace file: JSON with comments and trailing commas, a
	// servers object.
	write("projects/app/.ide/mcp.json", `{
  // servers this workspace uses
  "servers": {
    "db": {"type": "stdio", "command": "db-mcp", "args": ["--password", "hunter2hunter2", "--readonly"]},
    "docs": {"type": "http", "url": "https://docs.example.test/mcp", "headers": {"Authorization": "${input:docs-token}"}},
    "ci": {"command": "ci-mcp", "args": ["ghp_abcdefghijklmnopqrstuvwxyz0123"]}, /* a pasted token */
  },
}`)
	// An editor's settings: servers under "mcp", credentials by reference.
	write("settings/user.json", `{"mcp": {"servers": {
    "git": {"command": "git-mcp", "env": {"GIT_TOKEN": "${env:GIT_TOKEN}", "API_KEY": "$API_KEY"}},
    "legacy": {"url": "https://bot:s3cr3t-userinfo@legacy.example.test/mcp"}
  }}, "fontSize": 12}`)
	// Not MCP configuration: a package manifest and a broken file.
	write("projects/app/package.json", `{"name": "app", "scripts": {"start": "node ."}, "servers": "none"}`)
	write("projects/app/broken.json", `{"mcpServers": {"x": `)
	// Never walked: package trees.
	write("projects/app/node_modules/pkg/mcp.json", `{"mcpServers": {"vendored": {"command": "vendored-mcp"}}}`)
	return root
}

// P7 Done when (host detectors): a test host with two assistants configured
// shows each MCP server they use, with static tokens flagged and no value
// stored.
func TestMCPClientConfigSourceFindsServersAndFlagsStaticCredentials(t *testing.T) {
	root := writeMCPTestHost(t)
	found, err := NewMCPClientConfigSource(root).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]MCPServerFound{}
	for _, f := range found {
		byName[f.Name] = f
	}
	if len(found) != 8 || len(byName) != 8 {
		t.Fatalf("found %d servers: %+v", len(found), found)
	}
	want := map[string]struct {
		transport, command, host string
		fields                   string
	}{
		"files":   {"stdio", "npx", "", ""},
		"tracker": {"stdio", "tracker-mcp", "", "env:TRACKER_TOKEN"},
		"remote":  {"http", "", "https://mcp.example.test:8443", "header:Authorization,url:query:api_key"},
		"db":      {"stdio", "db-mcp", "", "arg:--password"},
		"docs":    {"http", "", "https://docs.example.test", ""},
		"ci":      {"stdio", "ci-mcp", "", "arg:#0"},
		"git":     {"stdio", "git-mcp", "", ""},
		"legacy":  {"http", "", "https://legacy.example.test", "url:userinfo"},
	}
	for name, w := range want {
		f := byName[name]
		if f.Transport != w.transport || f.Command != w.command || f.URLHost != w.host ||
			strings.Join(f.CredentialFields, ",") != w.fields || f.StaticCredential != (w.fields != "") {
			t.Errorf("%s = %+v, want %+v", name, f, w)
		}
	}
	if byName["remote"].Format != "mcpServers" || byName["db"].Format != "servers" || byName["git"].Format != "mcp.servers" {
		t.Fatalf("formats = %s %s %s", byName["remote"].Format, byName["db"].Format, byName["git"].Format)
	}
	// No value reaches anything reported.
	for _, rec := range MCPInventoryFindings(found) {
		blob := rec.Ref + rec.Provenance + rec.Fingerprint
		for k, v := range rec.Metadata {
			blob += k + "=" + v + ";"
		}
		for _, s := range mcpTestSecrets {
			if strings.Contains(blob, s) || strings.Contains(blob, strings.Fields(s)[len(strings.Fields(s))-1]) {
				t.Fatalf("a credential value reached the report: %q in %s", s, blob)
			}
		}
	}
	// A rescan of unchanged files has the same digest; a new server changes it.
	again, err := NewMCPClientConfigSource(root).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if MCPInventoryDigest(again) != MCPInventoryDigest(found) {
		t.Fatal("an unchanged rescan has a different digest")
	}
	if err := os.WriteFile(filepath.Join(root, "assistant-b.json"), []byte(`{"mcpServers": {"new": {"command": "new-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := NewMCPClientConfigSource(root).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 9 || MCPInventoryDigest(changed) == MCPInventoryDigest(found) {
		t.Fatalf("a new server did not change the digest (%d servers)", len(changed))
	}
}

func TestStripJSONCKeepsStringsAndDropsComments(t *testing.T) {
	in := `{"a": "x // not a comment", /* c */ "b": [1, 2,], // tail
"c": "/* still text */",}`
	got := string(stripJSONC([]byte(in)))
	for _, keep := range []string{`"x // not a comment"`, `"/* still text */"`, `[1, 2]`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("stripJSONC lost %s: %s", keep, got)
		}
	}
	if strings.Contains(got, "tail") || strings.Contains(got, " c ") {
		t.Fatalf("comments kept: %s", got)
	}
}
