// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/secretscan"
)

// P6: a GitHub push webhook signed with the hook's secret starts a repository
// secret scan; a missing or wrong signature is refused and starts nothing; a
// redelivery starts nothing new; the normalized route and polling stay.
func TestServedGitHubSecretScanHookVerifiesSignaturesP6(t *testing.T) {
	fake := &fakeSecretRepoScanner{called: make(chan string, 4), report: secretscan.Report{
		Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
	}}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
		d.SecretScanWebhooks = []config.SecretScanWebhook{{
			ID: "gh-acme", TenantID: servedTestTenant, Provider: "github",
			SecretRef: writeServedCredentialFile(t, "gh-acme-hook", "p6-hook-signing-secret"),
		}}
	})
	// The pushed repository: a real git repository on this machine (the lab
	// cannot reach github.com; a public https clone URL takes the same path).
	origin := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"}, {"config", "user.email", "p6@example.test"}, {"config", "user.name", "p6"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", origin}, args...)...).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(origin, "README.md"), []byte("payments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "README.md"}, {"commit", "-q", "-m", "init"}} {
		if out, err := exec.Command("git", append([]string{"-C", origin}, args...)...).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	head, err := exec.Command("git", "-C", origin, "rev-parse", "HEAD").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatal(err)
	}
	push := []byte(`{"ref":"refs/heads/main","after":"` + strings.TrimSpace(string(head)) + `","deleted":false,` +
		`"repository":{"full_name":"acme/payments","clone_url":"` + origin + `"}}`)
	sign := func(key string, body []byte) string {
		return "sha256=" + hex.EncodeToString(crypto.HMACSHA256([]byte(key), body))
	}
	deliver := func(hook, event, delivery, signature string, body []byte) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/scans/hooks/"+hook, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", event)
		req.Header.Set("X-GitHub-Delivery", delivery)
		if signature != "" {
			req.Header.Set("X-Hub-Signature-256", signature)
		}
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}
	runs := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM discovery_runs WHERE tenant_id = $1`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if status, body := deliver("gh-acme", "push", "d-1", sign("wrong-secret", push), push); status != http.StatusUnauthorized {
		t.Fatalf("wrong signature: HTTP %d %s", status, body)
	}
	if status, _ := deliver("gh-acme", "push", "d-2", "", push); status != http.StatusUnauthorized {
		t.Fatalf("missing signature: HTTP %d", status)
	}
	tampered := bytes.Replace(push, []byte("acme/payments"), []byte("acme/billing!"), 1)
	if status, _ := deliver("gh-acme", "push", "d-3", sign("p6-hook-signing-secret", push), tampered); status != http.StatusUnauthorized {
		t.Fatalf("a body changed after signing was accepted: HTTP %d", status)
	}
	if n := runs(); n != 0 {
		t.Fatalf("refused deliveries queued %d scans", n)
	}
	if status, _ := deliver("gh-unknown", "push", "d-4", sign("p6-hook-signing-secret", push), push); status != http.StatusNotFound {
		t.Fatalf("unknown hook: HTTP %d", status)
	}
	if status, body := deliver("gh-acme", "ping", "d-5", sign("p6-hook-signing-secret", []byte(`{"zen":"x"}`)), []byte(`{"zen":"x"}`)); status != http.StatusOK || !bytes.Contains(body, []byte(`"pong":true`)) {
		t.Fatalf("ping: HTTP %d %s", status, body)
	}

	status, body := deliver("gh-acme", "push", "d-6", sign("p6-hook-signing-secret", push), push)
	if status != http.StatusAccepted {
		t.Fatalf("signed push: HTTP %d %s", status, body)
	}
	var receipt struct {
		RunID      string `json:"run_id"`
		Repository string `json:"repository"`
		Provider   string `json:"provider"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.RunID == "" || receipt.Repository != "acme/payments" || receipt.Provider != "github" {
		t.Fatalf("receipt = %s (%v)", body, err)
	}
	var target string
	deadline := time.After(repositoryScanWait)
	for target == "" {
		h.srv.dispatchOnce(context.Background())
		select {
		case target = <-fake.called:
		case <-deadline:
			t.Fatal("the scan the push queued never ran")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, err := os.Stat(filepath.Join(target, "README.md")); err != nil {
		t.Fatalf("scanned %q, which is not a clone of the pushed repository (%v)", target, err)
	}
	// GitHub redelivers with the same delivery ID: the recorded answer, no new scan.
	if status, again := deliver("gh-acme", "push", "d-6", sign("p6-hook-signing-secret", push), push); status != http.StatusAccepted || !bytes.Equal(again, body) {
		t.Fatalf("redelivery: HTTP %d %s", status, again)
	}
	if n := runs(); n != 1 {
		t.Fatalf("scans queued = %d, want 1", n)
	}
	// The operator's check from the CLI: a signed ping, as GitHub would send it.
	keyFile := filepath.Join(t.TempDir(), "hook-secret")
	if err := os.WriteFile(keyFile, []byte("p6-hook-signing-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "secrets", "scans", "hooks", "test", "--hook", "gh-acme", "--secret-file", keyFile},
		cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"pong":true`) {
		t.Fatalf("trstctl secrets scans hooks test = %d: %s %s", code, stdout.String(), stderr.String())
	}
	t.Logf("P6_HOOK_OK run=%s target=%s", receipt.RunID, target)
}
