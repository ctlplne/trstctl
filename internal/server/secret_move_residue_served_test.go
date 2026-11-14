// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
)

// P6-L5: a moved leak's history residue is re-checked by every later
// completed scan of its repository, not only at move time. The server's
// shallow clone is deepened to every branch's full history: a commit on
// another branch that brings the value back is added, and once a history
// rewrite has removed every commit holding it, the residue is empty. Each
// check names its scan run and time; the value reaches no event or log.
// Real gitleaks, a real git repository behind a file:// URL (so the clone is
// shallow) and the native GitHub push hook.
func TestServedMovedSecretResidueIsRecheckedByLaterScansP6L5(t *testing.T) {
	bin := requireGitleaksBinary(t)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", bin)
	logs := &p6MoveLog{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	previous := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.Logger = logger
		d.SecretMoveClosureInterval = time.Hour
		d.SecretScanWebhooks = []config.SecretScanWebhook{{
			ID: "gh-p6l5", TenantID: servedTestTenant, Provider: "github",
			SecretRef: writeServedCredentialFile(t, "gh-p6l5-hook", "p6l5-residue-hook-secret"),
		}}
	})
	operator := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read", "secrets:write")
	leaked := sec07SlackBotToken

	origin := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", origin}, args...)...).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(origin, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "p6l5@example.test")
	git("config", "user.name", "p6l5")
	write("app.env", "APP=ledger\nSLACK_TOKEN="+leaked+"\n")
	git("add", "app.env")
	git("commit", "-q", "-m", "ledger config")
	leakCommit := git("rev-parse", "HEAD")

	delivery := 0
	push := func(commit string) string {
		t.Helper()
		delivery++
		body := []byte(`{"ref":"refs/heads/main","after":"` + commit + `","deleted":false,` +
			`"repository":{"full_name":"acme/ledger","clone_url":"file://` + origin + `"}}`)
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/scans/hooks/gh-p6l5", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("p6l5-residue-%d", delivery))
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(crypto.HMACSHA256([]byte("p6l5-residue-hook-secret"), body)))
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if resp.StatusCode != http.StatusAccepted || json.Unmarshal(out, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("push %s: HTTP %d %s", commit, resp.StatusCode, out)
		}
		return receipt.RunID
	}
	scanned := func(runID string) {
		t.Helper()
		deadline := time.Now().Add(repositoryScanWait)
		for time.Now().Before(deadline) {
			h.srv.dispatchOnce(context.Background())
			var status string
			if err := h.store.SystemPool().QueryRow(t.Context(),
				`SELECT status FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, runID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status == "succeeded" || status == "partial" {
				return
			}
			if status == "failed" {
				t.Fatalf("scan run %s failed", runID)
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("scan run %s never completed", runID)
	}
	type residueView struct {
		ID         string `json:"id"`
		Ref        string `json:"ref"`
		SecretMove *struct {
			HistoryResidue []struct {
				File   string `json:"file"`
				Commit string `json:"commit"`
			} `json:"history_residue"`
			CheckedAt *time.Time `json:"history_residue_checked_at"`
			RunID     string     `json:"history_residue_run_id"`
		} `json:"secret_move"`
	}
	view := func(id string) residueView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?id="+id, operator, nil)
		assertNoPlantedSecret(t, "finding", body)
		var page struct {
			Items []residueView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 || page.Items[0].SecretMove == nil {
			t.Fatalf("finding %s: HTTP %d %s", id, status, body)
		}
		return page.Items[0]
	}
	commits := func(f residueView) map[string]bool {
		out := map[string]bool{}
		for _, loc := range f.SecretMove.HistoryResidue {
			out[loc.Commit] = true
		}
		return out
	}

	// The leak is found, then moved: its residue as the move recorded it.
	first := push(leakCommit)
	scanned(first)
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=leaked_secret&run_id="+first, operator, nil)
	var page struct {
		Items []residueView `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("findings: HTTP %d %s", status, body)
	}
	leakID := ""
	for _, f := range page.Items {
		if strings.Contains(f.Ref, "app.env") && f.SecretMove == nil {
			leakID = f.ID
		}
	}
	if leakID == "" {
		t.Fatalf("no unmoved app.env finding in %s", body)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", operator, "--tenant", h.tenant,
		"secrets", "scans", "move", leakID, "--repo", origin, "--name", "ledger/slack-bot-token", "--gitleaks-bin", bin},
		cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl secrets scans move = %d: %s %s", code, stdout.String(), stderr.String())
	}
	if f := view(leakID); len(f.SecretMove.HistoryResidue) != 1 || !commits(f)[leakCommit] || f.SecretMove.CheckedAt != nil || f.SecretMove.RunID != "" {
		t.Fatalf("after the move: %+v", f.SecretMove)
	}

	// Another branch brings the value back; a scan of main sees it there.
	git("checkout", "-q", "-b", "copy")
	write("copy.env", "TOKEN="+leaked+"\n")
	git("add", "copy.env")
	git("commit", "-q", "-m", "copy the token")
	branchCommit := git("rev-parse", "HEAD")
	git("checkout", "-q", "main")
	second := push(leakCommit)
	scanned(second)
	f := view(leakID)
	if !commits(f)[leakCommit] || !commits(f)[branchCommit] || f.SecretMove.CheckedAt == nil || f.SecretMove.RunID != second {
		t.Fatalf("after a scan with the value on another branch: %+v (want %s and %s, run %s)", f.SecretMove, leakCommit, branchCommit, second)
	}
	firstCheck := *f.SecretMove.CheckedAt

	// History rewritten: main starts again without the value, the branch is gone.
	git("checkout", "-q", "--orphan", "rewritten")
	git("rm", "-q", "-f", "app.env")
	write("app.env", "APP=ledger\nSLACK_TOKEN=${secret.ledger/slack-bot-token}\n")
	git("add", "app.env")
	git("commit", "-q", "-m", "ledger config without the token")
	git("branch", "-D", "main", "copy")
	git("branch", "-m", "main")
	third := push(git("rev-parse", "HEAD"))
	scanned(third)
	f = view(leakID)
	if len(f.SecretMove.HistoryResidue) != 0 || f.SecretMove.CheckedAt == nil || !f.SecretMove.CheckedAt.After(firstCheck) || f.SecretMove.RunID != third {
		t.Fatalf("after the rewrite: %+v, want no residue, checked by run %s", f.SecretMove, third)
	}
	if h.logContains(t, leaked) {
		t.Fatal("the leaked value reached the event log")
	}
	if strings.Contains(logs.String(), leaked) {
		t.Fatal("the leaked value reached the server log")
	}
	t.Logf("P6L5_RESIDUE_OK finding=%s grew=%s cleared_by=%s", leakID, branchCommit[:8], third)
}
