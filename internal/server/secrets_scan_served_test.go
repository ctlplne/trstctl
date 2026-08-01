// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretscan"
)

var sec07SlackBotToken = strings.Join([]string{
	"xoxb",
	"123456789012",
	"123456789012",
	"abcdefghijklmnopqrstuvwx",
}, "-")

// TestServedGitleaksScanDetectsPlantedSecret is the SEC-07 acceptance proof:
// the running control plane invokes the real pinned Gitleaks binary through the
// served /api/v1/secrets/scans route, detects a planted secret with the default
// 140+ rule set active, records the finding through discovery events, and never
// echoes the secret value into responses or the event log.
func TestServedGitleaksScanDetectsPlantedSecret(t *testing.T) {
	bin := requireGitleaksBinary(t)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", bin)

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("SLACK_TOKEN="+sec07SlackBotToken+"\n"), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write planted secret fixture: %v", err)
	}

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:write", "discovery:read", "graph:read")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans", tok, "sec-07-gitleaks-scan", map[string]any{
		"path": repo,
	})
	if status != http.StatusCreated {
		t.Fatalf("start gitleaks scan: status %d body %s", status, body)
	}
	assertNoPlantedSecret(t, "scan response", body)

	var scan struct {
		RunID         string `json:"run_id"`
		Scanner       string `json:"scanner"`
		RulesActive   int    `json:"rules_active"`
		FindingsCount int    `json:"findings_count"`
		Findings      []struct {
			RuleID        string `json:"rule_id"`
			File          string `json:"file"`
			Line          int    `json:"line"`
			CredentialRef string `json:"credential_ref"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &scan); err != nil {
		t.Fatalf("decode scan response: %v (%s)", err, body)
	}
	if scan.Scanner != "gitleaks" || scan.RunID == "" {
		t.Fatalf("scan response = %+v, want gitleaks scanner and a run id", scan)
	}
	if scan.RulesActive < 140 {
		t.Fatalf("rules_active = %d, want the pinned default rule set with 140+ rules", scan.RulesActive)
	}
	if scan.FindingsCount < 1 || len(scan.Findings) < 1 {
		t.Fatalf("scan response has no findings: %+v", scan)
	}
	if scan.Findings[0].RuleID != "slack-bot-token" || !strings.HasSuffix(scan.Findings[0].File, "app.env") || scan.Findings[0].Line != 1 {
		t.Fatalf("first finding = %+v, want slack-bot-token in app.env line 1", scan.Findings[0])
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+scan.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list scan discovery findings: status %d body %s", status, body)
	}
	assertNoPlantedSecret(t, "discovery response", body)
	if !strings.Contains(string(body), "slack-bot-token@app.env") || !strings.Contains(string(body), `"kind":"leaked_secret"`) {
		t.Fatalf("discovery response does not expose the scan finding metadata: %s", body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get graph after scan: status %d body %s", status, body)
	}
	assertNoPlantedSecret(t, "graph response", body)
	if !strings.Contains(string(body), "slack-bot-token@app.env") || !strings.Contains(string(body), `"credential_kind":"leaked_secret"`) {
		t.Fatalf("graph response does not include the leaked-secret credential node: %s", body)
	}

	if !h.hasEvent(t, "discovery.finding.recorded") || !h.hasEvent(t, "discovery.run.completed") {
		t.Fatal("served gitleaks scan did not record discovery events")
	}
	if h.logContains(t, sec07SlackBotToken) {
		t.Fatal("the event log contains the planted secret value")
	}
}

func TestServedDeepSecretScanCAPSCAN03UsesHistoryAndCustomRules(t *testing.T) {
	repo := t.TempDir()
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
	fake := &fakeDeepSecretScanner{
		report: secretscan.Report{
			Scanner:       "gitleaks",
			EngineVersion: secretscan.GitleaksPinnedVersion,
			RulesActive:   secretscan.GitleaksDefaultRulesActive,
			Mode:          secretscan.ScanModeGitHistory,
			CustomRules:   true,
			Capabilities:  secretscan.ScanCapabilities(secretscan.ScanModeGitHistory, true),
			Findings: []secretscan.Finding{{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
				Scanner:       "gitleaks",
				RuleID:        "trstctl-custom-token",
				File:          filepath.Join(repo, "old.env"),
				Line:          3,
				Fingerprint:   "deep-fingerprint",
				CredentialRef: "trstctl-custom-token@old.env",
			}},
		},
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:write", "discovery:read")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans", tok, "cap-scan-03-deep", map[string]any{
		"path":              repo,
		"mode":              "git_history",
		"custom_rules_path": customRules,
	})
	if status != http.StatusCreated {
		t.Fatalf("start deep scan: status %d body %s", status, body)
	}
	var scan struct {
		RunID         string   `json:"run_id"`
		Mode          string   `json:"mode"`
		CustomRules   bool     `json:"custom_rules"`
		Capabilities  []string `json:"capabilities"`
		RulesActive   int      `json:"rules_active"`
		FindingsCount int      `json:"findings_count"`
	}
	if err := json.Unmarshal(body, &scan); err != nil {
		t.Fatalf("decode deep scan response: %v (%s)", err, body)
	}
	if scan.Mode != secretscan.ScanModeGitHistory || !scan.CustomRules || scan.RulesActive < secretscan.GitleaksMinRulesActive || scan.FindingsCount != 1 {
		t.Fatalf("deep scan response = %+v, want git_history custom scan with findings and rule floor", scan)
	}
	for _, want := range []string{"full-git-history", "custom-rules", "default-rules-100-plus", "entropy-rules"} {
		if !containsServerString(scan.Capabilities, want) {
			t.Fatalf("capabilities %v missing %q", scan.Capabilities, want)
		}
	}
	if fake.path != repo || fake.opts.Mode != secretscan.ScanModeGitHistory || fake.opts.CustomRulesPath != customRules {
		t.Fatalf("scanner call path=%q opts=%+v, want deep scan with custom rules", fake.path, fake.opts)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+scan.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list deep scan findings: status %d body %s", status, body)
	}
	if !strings.Contains(string(body), "trstctl-custom-token@old.env") || strings.Contains(string(body), "trst_") {
		t.Fatalf("deep scan discovery response has wrong redaction/metadata: %s", body)
	}
}

func requireGitleaksBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("TRSTCTL_GITLEAKS_BIN"), "/private/tmp/trstctl-tools/gitleaks"}
	if path, err := exec.LookPath("gitleaks"); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate) // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("SEC-07 acceptance requires the pinned Gitleaks binary; run tools/gitleaks/install.sh or set TRSTCTL_GITLEAKS_BIN")
	return ""
}

func assertNoPlantedSecret(t *testing.T, label string, body []byte) {
	t.Helper()
	if strings.Contains(string(body), sec07SlackBotToken) {
		t.Fatalf("%s leaked the planted secret value: %s", label, body)
	}
}

type fakeDeepSecretScanner struct {
	report secretscan.Report
	path   string
	opts   secretscan.ScanOptions
}

func (f *fakeDeepSecretScanner) Scan(_ context.Context, path string) (secretscan.Report, error) {
	f.path = path
	f.opts = secretscan.ScanOptions{Mode: secretscan.ScanModeWorkspace}
	return f.report, nil
}

func (f *fakeDeepSecretScanner) ScanWithOptions(_ context.Context, path string, opts secretscan.ScanOptions) (secretscan.Report, error) {
	f.path = path
	f.opts = opts
	return f.report, nil
}

func containsServerString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
