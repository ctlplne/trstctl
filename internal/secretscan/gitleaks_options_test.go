// SPDX-License-Identifier: MPL-2.0

package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitleaksRunnerDeepScanUsesGitHistoryAndDefaultExtendingCustomRules(t *testing.T) {
	repo := initSecretScanGitRepo(t)
	writeRepoFile(t, repo, "old.env", "API_KEY=old-value\n")
	gitSecretScan(t, repo, "add", "old.env")
	gitSecretScan(t, repo, "commit", "-m", "old secret")

	customRules := filepath.Join(t.TempDir(), "custom.toml")
	if err := os.WriteFile(customRules, []byte(`[[rules]]
id = "trstctl-custom-token"
description = "trstctl custom token"
regex = '''trst_[a-z0-9]{16}'''
secretGroup = 0
entropy = 3.5
`), 0o600); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(t.TempDir(), "args.txt")
	configCopy := filepath.Join(t.TempDir(), "config.toml")
	fake := fakeGitleaksCommand(t, argsPath, configCopy, `[]`)

	report, err := (&GitleaksRunner{Binary: fake}).ScanWithOptions(context.Background(), repo, ScanOptions{
		Mode:            "deep",
		CustomRulesPath: customRules,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != ScanModeGitHistory || !report.CustomRules {
		t.Fatalf("report mode/custom = %q/%v, want git_history with custom rules", report.Mode, report.CustomRules)
	}
	for _, want := range []string{"full-git-history", "custom-rules", "default-rules-100-plus", "entropy-rules"} {
		if !containsString(report.Capabilities, want) {
			t.Fatalf("capabilities %v missing %q", report.Capabilities, want)
		}
	}
	args := readText(t, argsPath)
	for _, want := range []string{"git", "--redact", "--config", "--log-opts", "--all", repo} {
		if !strings.Contains(args, want) {
			t.Fatalf("gitleaks args missing %q:\n%s", want, args)
		}
	}
	config := readText(t, configCopy)
	if !strings.Contains(config, "[extend]\nuseDefault = true") || !strings.Contains(config, `id = "trstctl-custom-token"`) {
		t.Fatalf("wrapper config did not extend defaults and include custom rule:\n%s", config)
	}
}

func TestGitleaksRunnerRejectsCustomRulesThatWeakenDefaults(t *testing.T) {
	customRules := filepath.Join(t.TempDir(), "custom.toml")
	if err := os.WriteFile(customRules, []byte("[extend]\ndisabledRules = [\"generic-api-key\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := prepareCustomRulesConfig(customRules)
	if err == nil || !strings.Contains(err.Error(), ErrInvalidCustomRules.Error()) {
		t.Fatalf("prepareCustomRulesConfig err = %v, want invalid custom rules", err)
	}
}

func fakeGitleaksCommand(t *testing.T, argsPath, configCopy, reportJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gitleaks")
	script := `#!/bin/sh
set -eu
report=""
config=""
printf '%s\n' "$@" > ` + shellQuoteForTest(argsPath) + `
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then
    shift
    report="$1"
  elif [ "$1" = "--config" ]; then
    shift
    config="$1"
  fi
  shift || true
done
if [ -n "$config" ]; then
  cp "$config" ` + shellQuoteForTest(configCopy) + `
fi
if [ -z "$report" ]; then
  echo "missing --report-path" >&2
  exit 2
fi
cat > "$report" <<'JSON'
` + reportJSON + `
JSON
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	return path
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func shellQuoteForTest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
