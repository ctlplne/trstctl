// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lineOf(t *testing.T, path, needle string) int {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("%s not in %s", needle, path)
	return 0
}

func TestLocateSlackExportMessageAndChannel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "channels.json"), []byte(`[{"id":"C0DEPLOY","name":"deploys"},{"id":"C0GENERAL","name":"general"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "deploys"), 0o700); err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(root, "deploys", "2026-10-30.json")
	content := `[
    {
        "type": "message",
        "text": "deploying now",
        "ts": "1730300000.000100"
    },
    {
        "type": "message",
        "text": "here is the token LEAKED-A174",
        "ts": "1730300050.000200",
        "thread_ts": "1730300000.000100"
    }
]
`
	if err := os.WriteFile(day, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := LocateThirdPartyObject("slack", root, "deploys/2026-10-30.json", lineOf(t, day, "LEAKED-A174"))
	if !ok || got["channel"] != "deploys" || got["channel_id"] != "C0DEPLOY" || got["message_ts"] != "1730300050.000200" || got["thread_ts"] != "1730300000.000100" {
		t.Fatalf("slack object = %+v, %v", got, ok)
	}
	if _, ok := LocateThirdPartyObject("slack", root, "../outside.json", 1); ok {
		t.Fatal("a path outside the artifact was read")
	}
	minified := filepath.Join(root, "deploys", "2026-10-31.json")
	if err := os.WriteFile(minified, []byte(`[{"ts":"1"},{"text":"LEAKED","ts":"2"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := LocateThirdPartyObject("slack", root, minified, 1); ok {
		t.Fatalf("a minified line was attributed to %+v", got)
	}
}

func TestLocateJiraExportIssue(t *testing.T) {
	root := t.TempDir()
	export := filepath.Join(root, "jira.json")
	content := `{
  "total": 2,
  "issues": [
    {
      "key": "OPS-173",
      "fields": {"summary": "rotate keys"}
    },
    {
      "key": "OPS-174",
      "fields": {"description": "the password is LEAKED-A174"}
    }
  ]
}
`
	if err := os.WriteFile(export, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := LocateThirdPartyObject("jira", export, "jira.json", lineOf(t, export, "LEAKED-A174"))
	if !ok || got["issue_key"] != "OPS-174" {
		t.Fatalf("jira object = %+v, %v", got, ok)
	}
	single := filepath.Join(root, "OPS-9.json")
	if err := os.WriteFile(single, []byte("{\n  \"key\": \"OPS-9\",\n  \"fields\": {\"description\": \"LEAKED\"}\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := LocateThirdPartyObject("jira", root, "OPS-9.json", 3); !ok || got["issue_key"] != "OPS-9" {
		t.Fatalf("single issue = %+v, %v", got, ok)
	}
	if _, ok := LocateThirdPartyObject("cicd", root, "jira.json", 1); ok {
		t.Fatal("a CI log was located from its content")
	}
}

func TestLocateJSONLinesExports(t *testing.T) {
	root := t.TempDir()
	slack := filepath.Join(root, "slack.jsonl")
	if err := os.WriteFile(slack, []byte(`{"channel":"ops","channel_id":"C0OPS","ts":"1.1","text":"fine"}`+"\n"+`{"channel":"ops","channel_id":"C0OPS","ts":"1.2","thread_ts":"1.1","text":"LEAKED"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := LocateThirdPartyObject("slack", slack, "slack.jsonl", 2); !ok || got["channel_id"] != "C0OPS" || got["message_ts"] != "1.2" || got["thread_ts"] != "1.1" {
		t.Fatalf("slack jsonl = %+v, %v", got, ok)
	}
	jira := filepath.Join(root, "issues.jsonl")
	if err := os.WriteFile(jira, []byte(`{"key":"OPS-1","fields":{}}`+"\n"+`{"key":"OPS-2","fields":{"description":"LEAKED"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := LocateThirdPartyObject("jira", jira, "issues.jsonl", 2); !ok || got["issue_key"] != "OPS-2" {
		t.Fatalf("jira jsonl = %+v, %v", got, ok)
	}
}
