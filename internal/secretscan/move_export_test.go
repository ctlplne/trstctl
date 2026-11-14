// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// P6-L7: a third-party finding's value is re-found in a local copy of the
// export the scan read, a directory (a Slack export) or one file (a Jira
// export), by the rule, the file inside the export and the line; a line with
// no value, a file outside the export, or an export outside the operator's
// roots is refused rather than guessed.
func TestLocateSecretInExportP6L7(t *testing.T) {
	bin := p6Gitleaks(t)
	root := t.TempDir()
	slack := filepath.Join(root, "slack-export")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(slack, "channels.json"), `[{"id":"C0DEPLOY","name":"deploys"}]`)
	write(filepath.Join(slack, "deploys", "2026-11-14.json"), "[\n  {\"type\": \"message\", \"text\": \"deploying\", \"ts\": \"1.1\"},\n  {\"type\": \"message\", \"text\": \"SLACK_TOKEN="+p6Token+"\", \"ts\": \"1.2\"}\n]\n")
	jira := filepath.Join(root, "jira", "issues.json")
	write(jira, "{\"issues\": [{\"key\": \"OPS-1\", \"fields\": {\"description\": \"token "+p6Token+"\"}}]}\n")

	runner := NewGitleaksRunner(bin)
	runner.AllowedRoots = []string{root}
	value, err := runner.LocateSecretInExport(t.Context(), slack, SecretLocation{RuleID: "slack-bot-token", File: "deploys/2026-11-14.json", Line: 3})
	if err != nil || !bytes.Equal(value, []byte(p6Token)) {
		t.Fatalf("in the Slack export: %d bytes, %v", len(value), err)
	}
	if value, err := runner.LocateSecretInExport(t.Context(), jira, SecretLocation{RuleID: "slack-bot-token", File: "issues.json", Line: 1}); err != nil || !bytes.Equal(value, []byte(p6Token)) {
		t.Fatalf("in the Jira export file: %d bytes, %v", len(value), err)
	}
	for name, want := range map[string]SecretLocation{
		"a line with no value":      {RuleID: "slack-bot-token", File: "deploys/2026-11-14.json", Line: 2},
		"another rule":              {RuleID: "github-pat", File: "deploys/2026-11-14.json", Line: 3},
		"a file outside the export": {RuleID: "slack-bot-token", File: "../jira/issues.json", Line: 1},
		"a file the export lacks":   {RuleID: "slack-bot-token", File: "random/2026-11-14.json", Line: 3},
	} {
		if _, err := runner.LocateSecretInExport(t.Context(), slack, want); !errors.Is(err, ErrSecretNotLocated) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	outside := NewGitleaksRunner(bin)
	outside.AllowedRoots = []string{t.TempDir()}
	if _, err := outside.LocateSecretInExport(t.Context(), slack, SecretLocation{RuleID: "slack-bot-token", File: "deploys/2026-11-14.json", Line: 3}); !errors.Is(err, ErrInvalidScanTarget) {
		t.Fatalf("an export outside the roots: %v", err)
	}
}
