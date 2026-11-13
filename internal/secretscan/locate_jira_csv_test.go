// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"os"
	"path/filepath"
	"testing"
)

// A174-L3: a finding in a Jira CSV export is located to the issue whose row
// holds its line, including a line inside a field quoted over several
// lines; the header, an export without an "Issue key" column and a value
// that is not an issue key locate nothing.
func TestLocateJiraCSVExportIssueA174L3(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	export := write("Jira.CSV", "\ufeffSummary,Issue key,Issue id,Description\r\n"+
		"rotate keys,OPS-173,10173,plain\r\n"+
		"leaked,OPS-174,10174,\"first line\r\nsecond line with LEAKED-A174L3\r\nthird \"\"quoted\"\" line\"\r\n"+
		"after,OPS-175,10175,ok\r\n")
	for line, want := range map[int]string{2: "OPS-173", 3: "OPS-174", lineOf(t, export, "LEAKED-A174L3"): "OPS-174", 5: "OPS-174", 6: "OPS-175"} {
		got, ok := LocateThirdPartyObject("jira", export, "Jira.CSV", line)
		if !ok || got["kind"] != "jira_issue" || got["issue_key"] != want || len(got) != 2 {
			t.Fatalf("line %d = %+v, %v; want %s", line, got, ok, want)
		}
	}
	if got, ok := LocateThirdPartyObject("jira", export, "Jira.CSV", 1); ok {
		t.Fatalf("the header located %+v", got)
	}
	noKey := write("no-key.csv", "Summary,Description\nleaked,LEAKED\n")
	if got, ok := LocateThirdPartyObject("jira", noKey, "no-key.csv", 2); ok {
		t.Fatalf("an export without an Issue key column located %+v", got)
	}
	badKey := write("bad-key.csv", "Summary,Issue key\nleaked,not a key\n")
	if got, ok := LocateThirdPartyObject("jira", badKey, "bad-key.csv", 2); ok {
		t.Fatalf("a value that is not an issue key located %+v", got)
	}
	// A JSON export is still read as JSON.
	json := write("issues.json", `{"issues":[{"key":"OPS-9","fields":{"description":"LEAKED"}}]}`)
	if got, ok := LocateThirdPartyObject("jira", json, "issues.json", 1); !ok || got["issue_key"] != "OPS-9" {
		t.Fatalf("json export = %+v, %v", got, ok)
	}
}
