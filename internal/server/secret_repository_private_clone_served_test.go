// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cgi" // #nosec G504 -- test-only stand-in host: serves the local git-http-backend; the toolchain is far past the CVE-2016-5386 fix (CWE-284)
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/secretscan"
)

// OD-1: a repository secret scan of a private repository clones it with its
// credential_ref. The served API takes a file: or secret:// reference for an
// https clone URL only; the outbox worker opens it for the clone alone; the
// scanner sees the private checkout; a signed GitHub push clones with its
// hook's clone_credential_ref; the discovery source keeps the reference,
// never the token; and a wrong token fails the run with a reason that does
// not carry it.
func TestServedPrivateRepositoryScanClonesWithItsCredentialRefOD1(t *testing.T) {
	work := t.TempDir()
	gitRun := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) // #nosec G204 -- the local git over the test's own repository (CWE-78)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+work)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	execPath, err := exec.Command("git", "--exec-path").Output() // #nosec G204 -- the local git (CWE-78)
	if err != nil {
		t.Skipf("git is not available: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend is not available: %v", err)
	}
	source := filepath.Join(work, "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	gitRun(source, "init", "-q", "-b", "main")
	gitRun(source, "config", "user.email", "od1@example.test")
	gitRun(source, "config", "user.name", "od1")
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("private payments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(source, "add", "README.md")
	gitRun(source, "commit", "-q", "-m", "init")
	hosted := filepath.Join(work, "hosted")
	if err := os.MkdirAll(hosted, 0o700); err != nil {
		t.Fatal(err)
	}
	gitRun(work, "clone", "-q", "--bare", source, filepath.Join(hosted, "payments.git"))

	// The private host: smart HTTP behind Basic authentication, over TLS.
	const token = "od1-served-repository-token" // #nosec G101 -- fabricated fixture token for the stand-in host (CWE-798)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	backendHandler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + hosted, "GIT_HTTP_EXPORT_ALL=1"}}
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		backendHandler.ServeHTTP(w, r)
	}))
	defer host.Close()
	ca := filepath.Join(work, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: host.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", ca)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("HOME", work)

	cloned := make(chan error, 4)
	fake := &fakeSecretRepoScanner{called: make(chan string, 4), report: secretscan.Report{
		Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
	}, inspect: func(path string) {
		body, err := os.ReadFile(filepath.Join(path, "README.md")) // #nosec G304 -- the server's own temporary clone (CWE-22)
		if err == nil && string(body) != "private payments\n" {
			err = os.ErrInvalid
		}
		cloned <- err
	}}
	const hookSecret = "od1-hook-signing-secret"
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
		d.SecretScanWebhooks = []config.SecretScanWebhook{{
			ID: "gh-private", TenantID: servedTestTenant, Provider: "github",
			SecretRef:          writeServedCredentialFile(t, "od1-hook-secret", hookSecret),
			CloneCredentialRef: writeServedCredentialFile(t, "od1-hook-clone-token", token),
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read")
	cloneURL := host.URL + "/payments.git"
	queue := func(idem string, body map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/github/webhook", tok, idem, body)
	}

	for name, body := range map[string]map[string]any{
		"http clone":   {"repository": "acme/payments", "clone_url": "http://127.0.0.1:1/payments.git", "credential_ref": "file:/nonexistent"}, // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
		"env ref":      {"repository": "acme/payments", "clone_url": cloneURL, "credential_ref": "env:OD1_TOKEN"},                              // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
		"user without": {"repository": "acme/payments", "clone_url": cloneURL, "credential_username": "deploy"},
	} {
		if status, out := queue("od1-refused-"+strings.ReplaceAll(name, " ", "-"), body); status != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d %s, want 400", name, status, out)
		}
	}

	runStatus := func(runID string) (string, string) {
		t.Helper()
		deadline := time.After(repositoryScanWait)
		for {
			h.srv.dispatchOnce(context.Background())
			var status, message string
			if err := h.store.SystemPool().QueryRow(t.Context(),
				`SELECT status, error FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, runID).Scan(&status, &message); err != nil {
				t.Fatal(err)
			}
			if status == "succeeded" || status == "failed" {
				return status, message
			}
			select {
			case <-deadline:
				t.Fatalf("run %s is still %s", runID, status)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	queued := func(status int, body []byte) string {
		t.Helper()
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("queue: HTTP %d %s", status, body)
		}
		return receipt.RunID
	}

	good := queued(queue("od1-good", map[string]any{"repository": "acme/payments", "clone_url": cloneURL,
		"credential_ref": writeServedCredentialFile(t, "od1-repo-token", token), "event": "push"}))
	if status, message := runStatus(good); status != "succeeded" {
		t.Fatalf("the private scan run is %s: %s", status, message)
	}
	select {
	case err := <-cloned:
		if err != nil {
			t.Fatalf("the scanner did not see the private checkout: %v", err)
		}
	case <-time.After(repositoryScanWait):
		t.Fatal("the private scan never reached the scanner")
	}
	var sourceConfig []byte
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT s.config FROM discovery_sources s JOIN discovery_runs r ON r.tenant_id = s.tenant_id AND r.source_id = s.id
		  WHERE r.tenant_id = $1 AND r.id = $2`, h.tenant, good).Scan(&sourceConfig); err != nil {
		t.Fatal(err)
	}
	var stored struct {
		CredentialRef string `json:"credential_ref"`
	}
	if err := json.Unmarshal(sourceConfig, &stored); err != nil || !strings.HasPrefix(stored.CredentialRef, "file:") || strings.Contains(string(sourceConfig), token) {
		t.Fatalf("the discovery source config = %s; want the reference and never the token", sourceConfig)
	}

	// A signed GitHub push of the private repository clones with the hook's
	// clone_credential_ref.
	head, err := exec.Command("git", "-C", source, "rev-parse", "HEAD").Output() // #nosec G204 -- the local git over the test's own repository (CWE-78)
	if err != nil {
		t.Fatal(err)
	}
	push := []byte(`{"ref":"refs/heads/main","after":"` + strings.TrimSpace(string(head)) + `","deleted":false,` +
		`"repository":{"full_name":"acme/payments","clone_url":"` + cloneURL + `"}}`)
	hookReq, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/scans/hooks/gh-private", bytes.NewReader(push))
	if err != nil {
		t.Fatal(err)
	}
	hookReq.Header.Set("Content-Type", "application/json")
	hookReq.Header.Set("X-GitHub-Event", "push")
	hookReq.Header.Set("X-GitHub-Delivery", "od1-delivery-1")
	hookReq.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(crypto.HMACSHA256([]byte(hookSecret), push)))
	hookResp, err := h.ts.Client().Do(hookReq)
	if err != nil {
		t.Fatal(err)
	}
	hookBody, _ := io.ReadAll(hookResp.Body)
	_ = hookResp.Body.Close()
	hookRun := queued(hookResp.StatusCode, hookBody)
	if status, message := runStatus(hookRun); status != "succeeded" {
		t.Fatalf("the hook's private scan run is %s: %s", status, message)
	}
	select {
	case err := <-cloned:
		if err != nil {
			t.Fatalf("the hook's scan did not see the private checkout: %v", err)
		}
	case <-time.After(repositoryScanWait):
		t.Fatal("the hook's private scan never reached the scanner")
	}

	bad := queued(queue("od1-bad", map[string]any{"repository": "acme/payments", "clone_url": cloneURL,
		"credential_ref": writeServedCredentialFile(t, "od1-wrong-token", "od1-not-the-token"), "event": "push"}))
	status, message := runStatus(bad)
	if status != "failed" || !strings.Contains(message, "credential_ref") || strings.Contains(message, "od1-not-the-token") || strings.Contains(message, token) {
		t.Fatalf("the wrong-token run is %s: %q; want failed naming the credential_ref and no token", status, message)
	}

	// The repository scanning posture the console shows says private
	// repositories clone with their credential_ref, no longer a follow-up.
	postureStatus, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/scans/repositories", tok, nil)
	var posture struct {
		Providers []struct {
			ID         string `json:"id"`
			AuthMode   string `json:"auth_mode"`
			IngestMode string `json:"ingest_mode"`
		} `json:"providers"`
		OperatorActions []string `json:"operator_actions"`
		Residuals       []string `json:"residuals"`
	}
	if postureStatus != http.StatusOK || json.Unmarshal(body, &posture) != nil || len(posture.Providers) != 3 {
		t.Fatalf("posture: HTTP %d %s", postureStatus, body)
	}
	for _, p := range posture.Providers {
		if !strings.Contains(p.AuthMode, "private repository clones over https") || !strings.Contains(p.IngestMode, "credential_ref") {
			t.Fatalf("posture provider %s = %+v; want private clones with credential_ref", p.ID, p)
		}
	}
	if text := strings.Join(append(posture.OperatorActions, posture.Residuals...), " | "); strings.Contains(text, "shortfall") ||
		strings.Contains(text, "private clone") || !strings.Contains(text, "credential_ref, opened for that clone only") {
		t.Fatalf("posture still calls private clones a follow-up: %s", text)
	}
}
