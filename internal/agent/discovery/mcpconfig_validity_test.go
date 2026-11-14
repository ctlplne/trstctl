// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// verdictChecker answers fixed verdicts by value and records each value it
// was handed, standing in for the validity checker.
type verdictChecker struct {
	mu       sync.Mutex
	seen     []string
	verdicts map[string][3]string // value -> provider, state, detail
}

func (c *verdictChecker) CheckCredential(_ context.Context, value []byte) (string, string, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, string(value))
	v, ok := c.verdicts[string(value)]
	return v[0], v[1], v[2], ok
}

// P14-L2: with a credential checker, each literal credential an MCP client
// configuration holds is handed to it while the file is read — an
// environment value, an Authorization header, a flag's value — under the
// field name the finding reports, and only the verdict is kept: the finding
// carries field=provider:state and the provider's detail beside the same
// risk, and a verdict that changes changes the digest so the agent reports
// again. A reference is never handed over, and without a
// checker nothing is checked.
func TestMCPStaticTokensAreCheckedWhereFoundP14L2(t *testing.T) {
	github := "ghp_" + "P14L2agentGitHubToken000000000000001"
	slack := "xoxb-" + "1414-1414-P14L2agentSlackBot"
	gitlab := "glpat-" + "P14L2agentGitLab0000"
	root := t.TempDir()
	config := `{"mcpServers": {
  "code": {"command": "code-mcp", "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "` + github + `"}},
  "chat": {"url": "https://chat.example.test/mcp", "headers": {"Authorization": "Bearer ` + slack + `"}},
  "repo": {"command": "repo-mcp", "args": ["--token=` + gitlab + `"]},
  "db": {"command": "db-mcp", "args": ["--password", "hunter2hunter2"]},
  "ref": {"command": "ref-mcp", "env": {"API_TOKEN": "${env:API_TOKEN}"}}}}`
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := &verdictChecker{verdicts: map[string][3]string{
		github:            {"github", "valid", "user p14l2-dev"},
		"Bearer " + slack: {"slack", "invalid", "Slack refused the token: token_revoked"},
		gitlab:            {"gitlab", "valid", `token "deploy" of user 42 (scopes read_api)`},
	}}
	found, err := NewMCPClientConfigSource(root).WithCredentialChecker(checker).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]MCPServerFound{}
	for _, f := range found {
		byName[f.Name] = f
	}
	want := map[string]string{"code": "env:GITHUB_PERSONAL_ACCESS_TOKEN=github:valid", "chat": "header:Authorization=slack:invalid",
		"repo": "arg:--token=gitlab:valid", "db": "", "ref": ""}
	for name, verdict := range want {
		f := byName[name]
		got := ""
		for _, v := range f.CredentialValidity {
			got = v.Field + "=" + v.Provider + ":" + v.State
		}
		if got != verdict || len(f.CredentialValidity) > 1 {
			t.Fatalf("%s's verdicts = %+v, want %q", name, f.CredentialValidity, verdict)
		}
	}
	checker.mu.Lock()
	seen := strings.Join(checker.seen, "\n")
	checker.mu.Unlock()
	if len(checker.seen) != 4 || strings.Contains(seen, "${env:API_TOKEN}") || !strings.Contains(seen, "hunter2hunter2") {
		t.Fatalf("the checker was handed %d values", len(checker.seen))
	}
	records := map[string]MCPInventoryFinding{}
	for _, r := range MCPInventoryFindings(found) {
		records[r.Metadata["server_name"]] = r
	}
	if code := records["code"]; code.RiskScore != 80 || code.Metadata["credential_validity"] != want["code"] ||
		code.Metadata["credential_validity_detail"] != "env:GITHUB_PERSONAL_ACCESS_TOKEN: user p14l2-dev" {
		t.Fatalf("code's finding = %d %v", code.RiskScore, code.Metadata)
	}
	if chat := records["chat"]; chat.RiskScore != 80 || chat.Metadata["credential_validity"] != want["chat"] {
		t.Fatalf("chat's finding = %d %v", chat.RiskScore, chat.Metadata)
	}
	if db := records["db"]; db.RiskScore != 80 || db.Metadata["credential_validity"] != "" || db.Metadata["credential_validity_detail"] != "" {
		t.Fatalf("db's finding = %d %v", db.RiskScore, db.Metadata)
	}
	for _, r := range records {
		for _, value := range []string{github, slack, gitlab, "hunter2hunter2"} {
			for _, v := range r.Metadata {
				if strings.Contains(v, value) {
					t.Fatal("a finding carries a credential value")
				}
			}
		}
	}
	// A token revoked since the last report changes the digest; the servers'
	// fingerprints do not change.
	before := MCPInventoryDigest(found)
	checker.verdicts[github] = [3]string{"github", "invalid", "GitHub refused the token: Bad credentials"}
	again, err := NewMCPClientConfigSource(root).WithCredentialChecker(checker).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if MCPInventoryDigest(again) == before {
		t.Fatal("a revoked token left the digest unchanged")
	}
	unchecked, err := NewMCPClientConfigSource(root).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range unchecked {
		if len(unchecked[i].CredentialValidity) != 0 || unchecked[i].Fingerprint != again[i].Fingerprint {
			t.Fatalf("without a checker %s = %+v", unchecked[i].Name, unchecked[i])
		}
	}
	// Verdicts past the 512 characters a metadata value holds are left out
	// whole, never cut.
	many := MCPServerFound{Name: "many", StaticCredential: true}
	for i := 0; i < 12; i++ {
		many.CredentialValidity = append(many.CredentialValidity, CredentialVerdict{Field: "env:" + strings.Repeat("A", 30) + string(rune('A'+i)),
			Provider: "github", State: "unknown", Detail: "GitHub answered Service Unavailable"})
	}
	meta := MCPInventoryFindings([]MCPServerFound{many})[0].Metadata
	if v := meta["credential_validity"]; len(v) > 512 || strings.Count(v, ",")+1 >= 12 || !strings.HasSuffix(v, "=github:unknown") {
		t.Fatalf("a long verdict list = %d characters: %q", len(v), v)
	}
}
