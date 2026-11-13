// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
	"trstctl.com/trstctl/internal/secretscan"
)

// A174-L5 Done-when: a first-party GitHub repository scan writes its
// findings back through code scanning. A push sent with an annotation
// connection records where each credential sits (repository, commit, ref,
// file, line); annotating the finding uploads it as a code scanning analysis
// of its own naming the rule, file and line and never the secret; resolving
// it uploads that analysis with no result, which closes the alert; a push
// with auto annotation uploads without an operator. A GitLab push, or a
// GitHub push without its commit, asking for an annotation is refused.
func TestServedRepositoryFindingIsAnnotatedThroughCodeScanningA174L5(t *testing.T) {
	const token = "a174l5-security-events-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := scanannotatetest.New(token, "")
	t.Cleanup(stand.Close)
	stand.SeedCommit("github", "acme/payments", "c174c174c174c174")
	stand.SeedCommit("github", "acme/billing", "e174e174e174e174")
	checkout := func(file, body string) (string, string) {
		root := t.TempDir()
		path := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return root, path
	}
	payments, paymentsFile := checkout("config/deploy.env", "# deploy\nTOKEN=LEAK-A174-l5\n")
	billing, billingFile := checkout("ci/build.env", "TOKEN=LEAK-A174-l5-auto\n")
	finding := func(file, name string, line int) secretscan.Finding {
		return secretscan.Finding{Scanner: "gitleaks", RuleID: "generic-api-key", File: file, Line: line, Fingerprint: "a174l5:" + name,
			CredentialRef: "generic-api-key@" + name}
	}
	fake := &fakeSecretRepoScanner{called: make(chan string, 4), report: secretscan.Report{Scanner: "gitleaks",
		EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
		Findings: []secretscan.Finding{finding(paymentsFile, "config/deploy.env", 2)}}}
	t.Setenv("TRSTCTL_A174L5_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_A174L5_TOKEN"),
		func(d *Deps) { d.SecretScanner = fake })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "discovery:write", "connectors:write",
		string(authz.PrivateEgress))
	annotation := func(auto bool) map[string]any {
		return map[string]any{"base_url": stand.URL(), "token_ref": "env:TRSTCTL_A174L5_TOKEN", "allow_private_endpoint": true, // #nosec G101 -- a credential reference to a fabricated fixture (CWE-798)
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())}, "auto": auto}
	}
	push := func(provider, key string, body map[string]any) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/"+provider+"/webhook", tok, key, body)
	}
	if status, body := push("gitlab", "a174l5-gitlab", map[string]any{"repository": "acme/payments", "checkout_path": payments,
		"ref": "refs/heads/main", "commit_sha": "c174c174c174c174", "annotation": annotation(false)}); status != http.StatusBadRequest ||
		!strings.Contains(string(body), "only GitHub") {
		t.Fatalf("a GitLab push asking for an annotation = %d %s", status, body)
	}
	if status, body := push("github", "a174l5-no-commit", map[string]any{"repository": "acme/payments", "checkout_path": payments,
		"ref": "refs/heads/main", "annotation": annotation(false)}); status != http.StatusBadRequest || !strings.Contains(string(body), "commit_sha") {
		t.Fatalf("a push without its commit asking for an annotation = %d %s", status, body)
	}

	type row struct {
		ID       string `json:"id"`
		Metadata struct {
			ProviderObject     map[string]string         `json:"provider_object"`
			AnnotationProvider string                    `json:"annotation_provider"`
			ProviderActions    map[string]map[string]any `json:"provider_actions"`
		} `json:"metadata"`
	}
	scan := func(key, repository, checkoutPath, sha string, auto bool) row {
		t.Helper()
		status, body := push("github", key, map[string]any{"repository": repository, "checkout_path": checkoutPath, "ref": "refs/heads/main",
			"commit_sha": sha, "event": "push", "annotation": annotation(auto)})
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("push %s = %d %s", key, status, body)
		}
		deadline := time.After(repositoryScanWait)
		for done := false; !done; {
			h.srv.dispatchOnce(context.Background())
			select {
			case <-fake.called:
				done = true
			case <-deadline:
				t.Fatalf("push %s was not scanned", key)
			case <-time.After(50 * time.Millisecond):
			}
		}
		for {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, tok, nil)
			if status != http.StatusOK || strings.Contains(string(body), "LEAK-A174") {
				t.Fatalf("findings: %d %s", status, body)
			}
			var list struct {
				Items []row `json:"items"`
			}
			if err := json.Unmarshal(body, &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Items) == 1 {
				return list.Items[0]
			}
			select {
			case <-deadline:
				t.Fatalf("push %s findings: %s", key, body)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	reread := func(id string) row {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100&kind=leaked_secret", tok, nil)
		var list struct {
			Items []row `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		for _, f := range list.Items {
			if f.ID == id {
				return f
			}
		}
		t.Fatalf("finding %s is gone", id)
		return row{}
	}

	leak := scan("a174l5-push", "acme/payments", payments, "c174c174c174c174", false)
	want := map[string]string{"kind": "repository_file", "repo": "acme/payments", "commit_sha": "c174c174c174c174", "ref": "refs/heads/main",
		"path": "config/deploy.env", "line": "2"}
	for k, v := range want {
		if leak.Metadata.ProviderObject[k] != v {
			t.Fatalf("provider object = %+v; want %+v", leak.Metadata.ProviderObject, want)
		}
	}
	if leak.Metadata.AnnotationProvider != "github" {
		t.Fatalf("annotation provider = %q", leak.Metadata.AnnotationProvider)
	}
	if _, uploaded := stand.CodeScanning("acme/payments", scanannotate.CodeScanningCategory(leak.ID)); uploaded {
		t.Fatal("a push without auto uploaded before an operator asked")
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+leak.ID+"/annotate", tok, "a174l5-annotate",
		map[string]any{"reason": "a174l5"}); status != http.StatusAccepted || !strings.Contains(string(body), `"provider":"github"`) {
		t.Fatalf("annotate = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain the annotation: %v", err)
	}
	results, uploaded := stand.CodeScanning("acme/payments", scanannotate.CodeScanningCategory(leak.ID))
	if !uploaded || len(results) != 1 || results[0].Rule != "generic-api-key" || results[0].Path != "config/deploy.env" || results[0].Line != 2 ||
		strings.Contains(results[0].Message, "LEAK-A174") {
		t.Fatalf("code scanning analysis = %+v (%v)", results, uploaded)
	}
	if state := reread(leak.ID).Metadata.ProviderActions["annotate"]; state["status"] != "confirmed" || state["provider_ref"] != "code-scanning:sarif-1" {
		t.Fatalf("annotate state = %+v", state)
	}

	// Resolving the finding closes the alert.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+leak.ID+"/resolution", tok, "a174l5-resolve",
		map[string]any{"action": "remediated", "reason": "a174l5 rotated", "evidence_ref": "rotation:a174l5"}); status != http.StatusOK {
		t.Fatalf("resolve = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain the settlement: %v", err)
	}
	if results, uploaded := stand.CodeScanning("acme/payments", scanannotate.CodeScanningCategory(leak.ID)); !uploaded || len(results) != 0 {
		t.Fatalf("after resolving = %+v (%v); want an empty analysis", results, uploaded)
	}
	if state := reread(leak.ID).Metadata.ProviderActions["resolve_annotation"]; state["status"] != "resolved" {
		t.Fatalf("resolve state = %+v", state)
	}

	// auto: true uploads without an operator.
	fake.report.Findings = []secretscan.Finding{finding(billingFile, "ci/build.env", 1)}
	auto := scan("a174l5-auto", "acme/billing", billing, "e174e174e174e174", true)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain the auto annotation: %v", err)
	}
	if results, uploaded := stand.CodeScanning("acme/billing", scanannotate.CodeScanningCategory(auto.ID)); !uploaded || len(results) != 1 ||
		results[0].Path != "ci/build.env" {
		t.Fatalf("auto analysis = %+v (%v)", results, uploaded)
	}
	if stand.Unauthorized() != 0 {
		t.Fatalf("the stand-in refused %d requests", stand.Unauthorized())
	}
}
