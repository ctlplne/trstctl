// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secretscan"
)

// A172-L1 Done-when: a credential leaked in a repository is correlated with
// the stored copies of the same credential. A secret_store source inspects a
// Vault KV double holding a GitLab token; a repository scan then finds that
// token in deploy.env, another GitLab token in app.env and a plain password
// in notes.txt. The deploy.env leak records the same credential fingerprint
// the stored copy carries (credential_fingerprint, credential_rule), the
// app.env leak records its own, the password records none, and the findings
// fingerprint filter lists exactly the stored copy and the leak that holds
// it. No token value reaches a finding or the event log.
func TestServedLeakedSecretIsCorrelatedWithTheStoredCredentialA172L1(t *testing.T) {
	gitlab := a172Token("gl"+"pat-", "A172l1shared", 26)
	other := a172Token("gl"+"pat-", "A172l1other", 26)
	var vaultSeen []string
	vault := a172VaultKVDouble(map[string]map[string]string{"ci/gitlab": {"token": gitlab, "user": "ci-bot"}}, &vaultSeen)
	t.Cleanup(vault.Close)
	t.Setenv("TRSTCTL_A172L1_VAULT_TOKEN", "vault-token")

	repo := t.TempDir()
	files := map[string][]string{
		"deploy.env": {"# deploy", "GITLAB_TOKEN=" + gitlab},
		"app.env":    {"GITLAB_TOKEN=" + other},
		"notes.txt":  {"admin password is correct-horse-battery-staple"},
	}
	for name, lines := range files {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// at reports a match the way gitleaks does: one or two columns past its
	// 0-based start (two on a later line) and one past its end.
	at := func(rule, name string, line int, value string) secretscan.Finding {
		text := files[name][line-1]
		col, shift := strings.Index(text, value), 2
		if line == 1 {
			shift = 1
		}
		return secretscan.Finding{Scanner: "gitleaks", RuleID: rule, File: filepath.Join(repo, name), Line: line, EndLine: line,
			Column: col + shift, EndColumn: col + len(value) + shift - 1, Fingerprint: "a172l1:" + name, CredentialRef: rule + "@" + name}
	}
	fake := &fakeSecretRepoScanner{called: make(chan string, 4), report: secretscan.Report{
		Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
		Findings: []secretscan.Finding{
			at("gitlab-pat", "deploy.env", 2, gitlab),
			at("gitlab-pat", "app.env", 1, other),
			at("generic-api-key", "notes.txt", 1, "correct-horse-battery-staple"),
		},
	}}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_A172L1_VAULT_TOKEN"),
		func(d *Deps) { d.SecretScanner = fake })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "discovery:write", "graph:read",
		string(authz.PrivateEgress))

	type finding struct {
		ID          string `json:"id"`
		Kind        string `json:"kind"`
		Ref         string `json:"ref"`
		Fingerprint string `json:"fingerprint"`
		Metadata    struct {
			CredentialFingerprint string `json:"credential_fingerprint"`
			CredentialRule        string `json:"credential_rule"`
		} `json:"metadata"`
	}
	list := func(query string) []finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100&"+query, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("findings %s: %d %s", query, status, body)
		}
		for _, value := range []string{gitlab, other, "correct-horse-battery-staple"} {
			if strings.Contains(string(body), value) {
				t.Fatalf("a scanned value reached the findings: %s", body)
			}
		}
		var out struct {
			Items []finding `json:"items"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out.Items
	}

	// The stored copy: a secret_store source with content inspection.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "a172l1-vault", "kind": "secret_store", "config": map[string]any{"providers": []map[string]any{{
			"provider": "hashicorp-vault", "vault_url": vault.URL, "mount": "secret", "path_prefix": "ci", "token_ref": "env:TRSTCTL_A172L1_VAULT_TOKEN", // #nosec G101 -- a credential reference to a fabricated fixture (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, vault.URL)}, "inspect_content": true,
		}}}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("create the secret store source: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID}); status != http.StatusCreated {
		t.Fatalf("run the secret store source: %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	storedCopies := list("kind=secret_store_api_key")
	if len(storedCopies) != 1 || storedCopies[0].Fingerprint == "" {
		t.Fatalf("stored credential findings = %+v", storedCopies)
	}
	stored := storedCopies[0]

	// The leak: a repository scan of the checkout.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/github/webhook", tok, "a172l1-scan", map[string]any{
		"repository": "acme/payments", "checkout_path": repo, "ref": "refs/heads/main", "commit_sha": "a172l1", "event": "push",
	})
	var receipt struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
		t.Fatalf("scan: %d %s", status, body)
	}
	deadline := time.After(repositoryScanWait)
	for done := false; !done; {
		h.srv.dispatchOnce(context.Background())
		select {
		case <-fake.called:
			done = true
		case <-deadline:
			t.Fatal("the scan was not delivered")
		case <-time.After(50 * time.Millisecond):
		}
	}
	var leaks map[string]finding
	for leaks == nil {
		if items := list("run_id=" + receipt.RunID); len(items) == 3 {
			leaks = map[string]finding{}
			for _, f := range items {
				leaks[f.Ref] = f
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("the scan's findings did not arrive")
		case <-time.After(50 * time.Millisecond):
		}
	}
	deploy, app, notes := leaks["gitlab-pat@deploy.env"], leaks["gitlab-pat@app.env"], leaks["generic-api-key@notes.txt"]
	if deploy.Kind != "leaked_secret" || deploy.Metadata.CredentialFingerprint != stored.Fingerprint || deploy.Metadata.CredentialRule != "gitlab_token" {
		t.Fatalf("the leak of the stored token = %+v; want credential fingerprint %s", deploy, stored.Fingerprint)
	}
	if app.Metadata.CredentialFingerprint == "" || app.Metadata.CredentialFingerprint == stored.Fingerprint {
		t.Fatalf("the other token's leak = %+v; want its own credential fingerprint", app)
	}
	if notes.Metadata.CredentialFingerprint != "" {
		t.Fatalf("a plain password named a credential: %+v", notes)
	}

	correlated := list("fingerprint=" + stored.Fingerprint)
	ids := make([]string, 0, len(correlated))
	for _, f := range correlated {
		ids = append(ids, f.ID)
	}
	want := []string{stored.ID, deploy.ID}
	slices.Sort(ids)
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("findings with the stored credential = %+v; want the stored copy and its leak", correlated)
	}
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		for _, value := range []string{gitlab, other} {
			if strings.Contains(string(e.Data), value) {
				t.Fatalf("event %s carries a token value", e.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
