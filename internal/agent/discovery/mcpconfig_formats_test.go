// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture values only, spliced in so no scanner reads a credential-shaped
// literal in this file.
var (
	p7l1AgentFakeTracker = "tkn_" + "1234567890abcdefghijklmnop"
	p7l1AgentFakeGitHub  = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123"
	p7l1AgentFakeGitLab  = "glpat-" + "abcdefghij0123456789"
)

// The values the TOML and YAML test host holds; none may appear in anything
// the source returns or the agent reports.
var mcpFormatTestSecrets = []string{p7l1AgentFakeTracker, "abc123secretquery", "xyzheadervalue", "hunter2hunter2",
	p7l1AgentFakeGitHub, "s3cr3t-userinfo", p7l1AgentFakeGitLab}

// P7-L1: MCP servers configured in TOML ([mcp_servers.<name>] tables) and in
// YAML (an mcpServers mapping, or a servers sequence of named entries) are
// found like JSON's, with static credentials named by field and no value
// reported; TOML and YAML that are not MCP configuration, or do not parse,
// name nothing.
func TestMCPClientConfigInTOMLAndYAMLP7L1(t *testing.T) {
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
	write("cli-assistant/config.toml", `model = "large" # unrelated

[mcp_servers.files]
command = "/usr/local/bin/npx"
args = ["-y", "files-server", "/srv/shared"]

[mcp_servers.tracker]
command = "tracker-mcp"
env = { TRACKER_TOKEN = "`+p7l1AgentFakeTracker+`", GIT_AUTHOR_NAME = "Build Bot" }

[mcp_servers.remote]
url = "https://mcp.example.test:8443/mcp?api_key=abc123secretquery&region=eu"

[mcp_servers.remote.http_headers]
Authorization = "Bearer xyzheadervalue"

[mcp_servers."db.prod"]
command = 'db-mcp'
args = [
  "--password", "hunter2hunter2", # a pasted password
  "--readonly",
]

[[profiles]]
name = "not a server"
`)
	write("assistant/config.yaml", `# assistant settings
theme: dark
mcpServers:
  git:
    command: git-mcp
    env:
      GIT_TOKEN: ${env:GIT_TOKEN}
      API_KEY: "`+p7l1AgentFakeGitHub+`"
  docs:
    type: http
    url: 'https://docs.example.test/mcp'
    headers: {Authorization: "${input:docs-token}"}
`)
	write("ide/servers.yml", `servers:
- name: legacy
  url: https://bot:s3cr3t-userinfo@legacy.example.test/mcp
- name: ci
  command: ci-mcp
  args: [--token, "`+p7l1AgentFakeGitLab+`"]
`)
	// Not MCP configuration, or not readable: nothing.
	write("deploy/compose.yaml", "services:\n  web:\n    image: nginx\n    command: [nginx, -g, daemon off;]\n")
	write("deploy/values.yml", "servers: none\nreplicas: 3\n")
	write("broken/bad.toml", "[mcp_servers.x\ncommand = \"a\"\n")
	write("broken/anchors.yaml", "base: &base\n  command: x\nmcpServers:\n  a: *base\n")
	write("tool/pyproject.toml", "[tool.poetry]\nname = \"app\"\n[tool.poetry.scripts]\nserve = \"app:main\"\n")

	found, err := NewMCPClientConfigSource(root).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]MCPServerFound{}
	for _, f := range found {
		byName[f.Name] = f
	}
	want := map[string]struct {
		format, transport, command, host, fields string
	}{
		"files":   {"mcp_servers", "stdio", "npx", "", ""},
		"tracker": {"mcp_servers", "stdio", "tracker-mcp", "", "env:TRACKER_TOKEN"},
		"remote":  {"mcp_servers", "http", "", "https://mcp.example.test:8443", "header:Authorization,url:query:api_key"},
		"db.prod": {"mcp_servers", "stdio", "db-mcp", "", "arg:--password"},
		"git":     {"mcpServers", "stdio", "git-mcp", "", "env:API_KEY"},
		"docs":    {"mcpServers", "http", "", "https://docs.example.test", ""},
		"legacy":  {"servers", "http", "", "https://legacy.example.test", "url:userinfo"},
		"ci":      {"servers", "stdio", "ci-mcp", "", "arg:--token"},
	}
	if len(found) != len(want) || len(byName) != len(want) {
		t.Fatalf("found %d servers: %+v", len(found), found)
	}
	for name, w := range want {
		f := byName[name]
		if f.Format != w.format || f.Transport != w.transport || f.Command != w.command || f.URLHost != w.host ||
			strings.Join(f.CredentialFields, ",") != w.fields || f.StaticCredential != (w.fields != "") {
			t.Errorf("%s = %+v, want %+v", name, f, w)
		}
	}
	for _, rec := range MCPInventoryFindings(found) {
		blob := rec.Ref + rec.Provenance + rec.Fingerprint
		for k, v := range rec.Metadata {
			blob += k + "=" + v + ";"
		}
		for _, s := range mcpFormatTestSecrets {
			if strings.Contains(blob, s) {
				t.Fatalf("a credential value reached the report: %q in %s", s, blob)
			}
		}
	}
}

// P7-L1: the TOML reader decodes TOML's strings (escapes, literal and
// multi-line forms), dotted and quoted keys, multi-line arrays and inline
// tables; a document it cannot read is refused whole.
func TestTOMLReaderP7L1(t *testing.T) {
	pairs, ok := parseTOMLPairs([]byte("when = 1979-05-27 07:32:00Z\na.\"b.c\" = \"x\\u00e9\\ty\\\"\" # c\nlit = 'C:\\path'\nml = \"\"\"\nline1\\\n   line2\"\"\"\n" +
		"mll = '''\nraw\\n'''\narr = [\n 1, # one\n \"two\",\n]\nt = { k = { deep = \"v\" }, n = 2 }\n"))
	if !ok {
		t.Fatal("a valid document was refused")
	}
	got := map[string]string{}
	for _, p := range pairs {
		v := string(p.val.bytes)
		if p.val.isArray {
			var parts []string
			for _, it := range p.val.items {
				parts = append(parts, string(it.bytes))
			}
			v = "[" + strings.Join(parts, "|") + "]"
		}
		got[strings.Join(p.key, "/")] = v
	}
	for key, want := range map[string]string{
		"when": "1979-05-27 07:32:00Z", "a/b.c": "x\u00e9\ty\"", "lit": `C:\path`, "ml": "line1line2", "mll": `raw\n`, "arr": "[1|two]", "t/k/deep": "v", "t/n": "2",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q (all %q)", key, got[key], want, got)
		}
	}
	for _, bad := range []string{"a = \"open\n", "[t\n", "a = [1, 2\n", "= 1\n", "a = { b = 1\n", "a = \"\\q\"\n", "a = \"\\uD800\"\n", "a = 1 b = 2\n"} {
		if _, ok := parseTOMLPairs([]byte(bad)); ok {
			t.Errorf("%q was read", bad)
		}
	}
}

// P7-L1: the YAML reader reads block mappings and sequences by indentation
// (a sequence may sit at its key's indentation), flow collections, quoted
// scalars with their escapes and block scalars; anchors and a second
// document are refused.
func TestYAMLReaderP7L1(t *testing.T) {
	root := parseYAMLTree([]byte("---\ntop:\n  \"quoted key\": \"a\\\"b\\u00e9\"\n  single: 'it''s'\n  list:\n  - one\n  - k: v\n    k2: v2 # comment\n" +
		"  flow: [x, 'y', {z: \"w\"}]\n  block: |\n    l1\n    l2\nend: plain value\n"))
	if root == nil {
		t.Fatal("a valid document was refused")
	}
	top := root.get("top")
	scalar := func(n *yamlNode) string {
		if n == nil {
			return "<nil>"
		}
		return string(n.scalar)
	}
	list := top.get("list")
	flow := top.get("flow")
	for name, pair := range map[string][2]string{
		"quoted":  {scalar(top.get("quoted key")), "a\"b\u00e9"},
		"single":  {scalar(top.get("single")), "it's"},
		"list[0]": {scalar(list.items[0]), "one"},
		"list[1]": {scalar(list.items[1].get("k")) + "," + scalar(list.items[1].get("k2")), "v,v2"},
		"flow":    {scalar(flow.items[0]) + scalar(flow.items[1]) + scalar(flow.items[2].get("z")), "xyw"},
		"block":   {scalar(top.get("block")), "l1\nl2"},
		"end":     {scalar(root.get("end")), "plain value"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
	for _, bad := range []string{"a: &x 1\nb: *x\n", "a: 1\n---\nb: 2\n", "a:\n\tb: 1\n", "a: [1, 2\n", "just text\n", "a: \"open\n"} {
		if n := parseYAMLTree([]byte(bad)); n != nil {
			t.Errorf("%q was read", bad)
		}
	}
}

// FuzzParseTOMLPairs reads arbitrary bytes as TOML: nothing panics, and what
// it reads stays within its bounds.
func FuzzParseTOMLPairs(f *testing.F) {
	for _, seed := range []string{
		"[mcp_servers.a]\ncommand = \"x\"\nargs = [\"--k\", 'v']\nenv = { K = \"v\" }\n",
		"a.\"b\" = \"\"\"\nx\\\n y\"\"\"\n", "arr = [[1, 2], [\"a\"]]\n", "[[t]]\nx = 1\n", "a = '''\nq'''\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pairs, ok := parseTOMLPairs(data)
		if !ok {
			return
		}
		if len(pairs) > maxTOMLPairs {
			t.Fatalf("%d pairs past the bound", len(pairs))
		}
		_ = tomlMCPServers(pairs)
		for i := range pairs {
			if len(pairs[i].key) == 0 {
				t.Fatal("a pair with no key")
			}
			pairs[i].val.wipe()
		}
	})
}

// FuzzParseYAMLTree reads arbitrary bytes as YAML: nothing panics, and a tree
// it reads is walked and wiped.
func FuzzParseYAMLTree(f *testing.F) {
	for _, seed := range []string{
		"mcpServers:\n  a:\n    command: x\n    args: [--k, 'v']\n", "servers:\n- name: a\n  url: https://h/x\n",
		"a: |\n  b\n  c\n", "a: {b: [c, {d: e}]}\n", "\"k\": 'it''s'\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		root := parseYAMLTree(data)
		if root == nil {
			return
		}
		_ = yamlMCPServers(root)
		root.wipe()
	})
}
