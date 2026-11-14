// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/secretscan/validity"
)

// p14l1Scanner reports a finding for each line holding one of its markers,
// under that marker's rule and at the marker's column, the way Gitleaks
// reports its default rules.
type p14l1Scanner struct {
	rules map[string]string // marker -> rule
}

func (s *p14l1Scanner) Scan(_ context.Context, target string) (secretscan.Report, error) {
	report := secretscan.Report{Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive}
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G122 G304 -- test fixture under t.TempDir (CWE-22)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(target, path)
		for i, line := range strings.Split(string(data), "\n") {
			for marker, rule := range s.rules {
				if at := strings.Index(line, marker); at >= 0 {
					report.Findings = append(report.Findings, secretscan.Finding{Scanner: "gitleaks", RuleID: rule, File: rel, Line: i + 1,
						Column: at + 1, CredentialRef: rule + "@" + rel, Fingerprint: rel + ":" + rule})
				}
			}
		}
		return nil
	})
	return report, err
}

// P14-L1: a CI artifact holding a GitHub token, a revoked GitLab token, a
// Slack bot token, a Microsoft Entra ID client secret and a Google
// service-account key is scanned, and each finding is checked by its own
// provider where it was found: the live credentials valid with their user,
// workspace, application or service account, the revoked token invalid. No
// finding carries a secret, each token went only to its own provider's
// identity endpoint, and Google saw only a signed assertion.
func TestServedLeakedTokensAreCheckedByTheirOwnProvidersP14L1(t *testing.T) {
	const (
		// Fabricated credentials in each provider's shape, built from two
		// literals so secret scanners do not take the fixtures for credentials.
		github  = "ghp_" + "P14L1servedGitHubToken00000000000001"
		gitlab  = "glpat-" + "P14L1servedRevoked00"
		slack   = "xoxb-" + "1414-1414-P14L1servedSlackBot"
		entra   = "p14" + "1Q~" + "P14L1servedEntraSecret.000000000"
		app     = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9"
		org     = "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
		account = "p14l1-ci@p14l1-project.iam.gserviceaccount.com"
	)
	var mu sync.Mutex
	var calls []string
	tokens := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user" && bearer == github:
			_ = json.NewEncoder(w).Encode(map[string]any{"login": "p14l1-ci"})
		case r.URL.Path == "/api/v4/personal_access_tokens/self" && r.Header.Get("PRIVATE-TOKEN") == gitlab:
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token", "error_description": "Token was revoked. You have to re-authorize from the user."})
		case r.URL.Path == "/api/auth.test" && r.Method == http.MethodPost && bearer == slack:
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "team": "P14L1 Ops", "team_id": "T0P14L1", "user": "deploybot"})
		default:
			t.Errorf("unexpected identity call: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	t.Cleanup(tokens.Close)
	idp := infratest.StartEntra(app, entra)
	t.Cleanup(idp.Close)
	google, err := infratest.StartGoogleServiceAccount(account)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(google.Close)
	keyPEM := google.ServiceAccountKeyPEM()

	artifact := t.TempDir()
	keyJSON, err := json.MarshalIndent(map[string]string{"type": "service_account", "private_key": string(keyPEM), "client_email": account, // #nosec G101 -- a key file for a key generated at run time for the stand-in, not a credential (CWE-798)
		"private_key_id": strings.Repeat("cd", 20), "token_uri": "https://elsewhere.example.test/token"}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"ci.env":      "GITHUB_TOKEN=" + github + "\nGITLAB_TOKEN=" + gitlab + "\nSLACK_BOT_TOKEN=" + slack + "\n",
		"azure.env":   "AZURE_TENANT_ID=" + org + "\nAZURE_CLIENT_ID=" + app + "\nAZURE_CLIENT_SECRET=" + entra + "\n",
		"sa-key.json": string(keyJSON) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(artifact, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checker := validity.New(validity.Config{
		Providers: []string{validity.ProviderGitHub, validity.ProviderGitLab, validity.ProviderSlack, validity.ProviderAzure, validity.ProviderGCP},
		Endpoints: map[string]string{validity.ProviderGitHub: tokens.URL, validity.ProviderGitLab: tokens.URL, validity.ProviderSlack: tokens.URL,
			validity.ProviderAzure: idp.URL(), validity.ProviderGCP: google.URL()},
		Allowlist: []string{tokens.URL, idp.URL(), google.URL()}, Client: tokens.Client(),
		Rates: map[string]float64{validity.ProviderGitHub: 50, validity.ProviderGitLab: 50, validity.ProviderSlack: 50, validity.ProviderAzure: 50, validity.ProviderGCP: 50}})
	scanner := &p14l1Scanner{rules: map[string]string{"ghp_": "github-pat", "glpat-": "gitlab-pat", "xoxb-": "slack-bot-token",
		"Q~": "azure-ad-client-secret", "BEGIN PRIVATE KEY": "private-key"}}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = scanner
		d.SecretValidity = checker
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/cicd_log/ingest", tok, "p14l1-ingest",
		map[string]any{"source": "p14l1-ci", "artifact_path": artifact})
	var receipt struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
		t.Fatalf("ingest = %d %s", status, body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		h.srv.dispatchOnce(context.Background())
		var runStatus string
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT status FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, receipt.RunID).Scan(&runStatus)
		if runStatus == "succeeded" {
			break
		}
		if runStatus == "failed" || time.Now().After(deadline) {
			t.Fatalf("the scan run is %q", runStatus)
		}
		time.Sleep(100 * time.Millisecond)
	}
	rows, err := h.store.SystemPool().Query(t.Context(), `SELECT metadata::text FROM discovery_findings WHERE tenant_id = $1 AND run_id = $2`, h.tenant, receipt.RunID)
	if err != nil {
		t.Fatal(err)
	}
	type verdict struct {
		Provider, State, Detail string
	}
	byRule := map[string]verdict{}
	keyBody := strings.Split(string(keyPEM), "\n")[1]
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{github, gitlab, slack, entra, keyBody} {
			if strings.Contains(raw, value) {
				t.Fatalf("a finding carries a secret: %.120s", raw)
			}
		}
		var m struct {
			RuleID   string  `json:"rule_id"`
			Validity verdict `json:"validity"`
		}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		byRule[m.RuleID] = m.Validity
	}
	rows.Close()
	want := map[string]verdict{
		"github-pat":             {validity.ProviderGitHub, validity.StateValid, "user p14l1-ci"},
		"gitlab-pat":             {validity.ProviderGitLab, validity.StateInvalid, "GitLab refused the token: Token was revoked"},
		"slack-bot-token":        {validity.ProviderSlack, validity.StateValid, "workspace P14L1 Ops (T0P14L1), user deploybot"},
		"azure-ad-client-secret": {validity.ProviderAzure, validity.StateValid, "application " + app + " in tenant " + org},
		"private-key":            {validity.ProviderGCP, validity.StateValid, "service account " + account},
	}
	if len(byRule) != len(want) {
		t.Fatalf("findings = %+v", byRule)
	}
	for rule, w := range want {
		got := byRule[rule]
		if got.Provider != w.Provider || got.State != w.State || !strings.Contains(got.Detail, w.Detail) {
			t.Fatalf("%s's validity = %+v; want %+v", rule, got, w)
		}
	}
	mu.Lock()
	identityCalls := strings.Join(calls, ", ")
	mu.Unlock()
	if len(calls) != 3 || !strings.Contains(identityCalls, "GET /user") || !strings.Contains(identityCalls, "GET /api/v4/personal_access_tokens/self") ||
		!strings.Contains(identityCalls, "POST /api/auth.test") {
		t.Fatalf("identity calls = %s", identityCalls)
	}
	forms := google.Assertions()
	if len(forms) != 1 || strings.Contains(forms[0], "PRIVATE") || strings.Contains(forms[0], keyBody) || !strings.Contains(forms[0], "assertion=") {
		t.Fatalf("Google saw %d token requests carrying more than an assertion", len(forms))
	}
	t.Logf("P14L1_PROVIDER_CHECKS_OK github=%s gitlab=%s slack=%s azure=%s gcp=%s", byRule["github-pat"].State, byRule["gitlab-pat"].State,
		byRule["slack-bot-token"].State, byRule["azure-ad-client-secret"].State, byRule["private-key"].State)
}
