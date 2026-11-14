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

type p6l6Finding struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Ref               string `json:"ref"`
	RiskScore         int    `json:"risk_score"`
	TriageStatus      string `json:"triage_status"`
	TriageActor       string `json:"triage_actor"`
	TriageEvidenceRef string `json:"triage_evidence_ref"`
	Regressed         bool   `json:"regressed"`
	Metadata          struct {
		MovedFindingID string `json:"moved_finding_id"`
		SecretName     string `json:"secret_name"`
		CommitCount    int    `json:"commit_count"`
		HistoryResidue []struct {
			Commit string `json:"commit"`
			File   string `json:"file"`
		} `json:"history_residue"`
	} `json:"metadata"`
	SecretMove *struct {
		HistoryResidue []struct {
			Commit string `json:"commit"`
		} `json:"history_residue"`
	} `json:"secret_move"`
}

// P6-L6: once a moved finding closes, the history commits that still hold
// the rotated value become their own open finding on the same source
// (secret_history_residue, risk 35), naming the moved finding and the
// commits. A later scan that finds no commit holding the value closes it as
// remediated with that run as evidence; a commit that brings the value back
// records it again, regressed. Real gitleaks, a real repository behind a
// file:// URL and the native GitHub push hook.
func TestServedHistoryResidueBecomesItsOwnFindingP6L6(t *testing.T) {
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
			ID: "gh-p6l6", TenantID: servedTestTenant, Provider: "github",
			SecretRef: writeServedCredentialFile(t, "gh-p6l6-hook", "p6l6-residue-hook-secret"),
		}}
	})
	operator := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read", "secrets:write")
	consumer := seedScopedTokenSubject(t, h.store, h.tenant, "billing-api", "secrets:read")
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
	git("config", "user.email", "p6l6@example.test")
	git("config", "user.name", "p6l6")
	write("app.env", "APP=billing\nSLACK_TOKEN="+leaked+"\n")
	git("add", "app.env")
	git("commit", "-q", "-m", "billing config")
	leakCommit := git("rev-parse", "HEAD")

	delivery := 0
	push := func(commit string) string {
		t.Helper()
		delivery++
		body := []byte(`{"ref":"refs/heads/main","after":"` + commit + `","deleted":false,` +
			`"repository":{"full_name":"acme/billing","clone_url":"file://` + origin + `"}}`)
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/scans/hooks/gh-p6l6", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("p6l6-residue-%d", delivery))
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(crypto.HMACSHA256([]byte("p6l6-residue-hook-secret"), body)))
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
		deadline := time.Now().Add(repositoryScanWait)
		for time.Now().Before(deadline) {
			h.srv.dispatchOnce(context.Background())
			var status string
			if err := h.store.SystemPool().QueryRow(t.Context(),
				`SELECT status FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, receipt.RunID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status == "succeeded" || status == "partial" {
				return receipt.RunID
			}
			if status == "failed" {
				t.Fatalf("scan run %s failed", receipt.RunID)
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("scan run %s never completed", receipt.RunID)
		return ""
	}
	findings := func(query string) []p6l6Finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?"+query, operator, nil)
		assertNoPlantedSecret(t, "findings", body)
		var page struct {
			Items []p6l6Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("findings %s: HTTP %d %s", query, status, body)
		}
		return page.Items
	}

	// Found, moved, rotated and read: still open, its residue listed on it.
	first := push(leakCommit)
	moved := findings("kind=leaked_secret&run_id=" + first)
	if len(moved) != 1 {
		t.Fatalf("leaked findings of the first run = %+v", moved)
	}
	leakID := moved[0].ID
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", operator, "--tenant", h.tenant,
		"secrets", "scans", "move", leakID, "--repo", origin, "--name", "billing/slack-bot-token", "--gitleaks-bin", bin},
		cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl secrets scans move = %d: %s %s", code, stdout.String(), stderr.String())
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/billing/slack-bot-token", operator, "p6l6-rotate",
		map[string]any{"value": "rotated-p6l6-value-not-a-token"}); status != http.StatusOK {
		t.Fatalf("rotate: HTTP %d %s", status, body)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/billing/slack-bot-token", consumer, nil); status != http.StatusOK {
		t.Fatalf("consumer read: HTTP %d", status)
	}

	// The file is cleaned and scanned: the moved finding closes, and its
	// residue opens as its own finding.
	write("app.env", "APP=billing\nSLACK_TOKEN=${secret.billing/slack-bot-token}\n")
	git("commit", "-q", "-am", "read the token from the secret store")
	clean := push(git("rev-parse", "HEAD"))
	if residue := findings("kind=secret_history_residue&run_id=" + clean); len(residue) != 0 {
		t.Fatalf("a residue finding before the moved finding closed: %+v", residue)
	}
	if n, err := h.srv.CloseMovedSecretFindingsOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("closure = %d %v, want the moved finding closed", n, err)
	}
	residue := findings("kind=secret_history_residue&run_id=" + clean)
	if len(residue) != 1 {
		t.Fatalf("residue findings after the closure = %+v", residue)
	}
	r := residue[0]
	if r.TriageStatus == "remediated" || r.RiskScore != 35 || r.Ref != moved[0].Ref || r.Metadata.MovedFindingID != leakID ||
		r.Metadata.SecretName != "billing/slack-bot-token" || r.Metadata.CommitCount != 1 ||
		len(r.Metadata.HistoryResidue) != 1 || r.Metadata.HistoryResidue[0].Commit != leakCommit {
		t.Fatalf("residue finding = %+v", r)
	}
	if again := findings("id=" + leakID); len(again) != 1 || again[0].TriageStatus != "remediated" {
		t.Fatalf("the moved finding = %+v", again)
	}

	// History rewritten: a scan finds no commit holding the value and closes it.
	git("checkout", "-q", "--orphan", "rewritten")
	git("rm", "-q", "-f", "app.env")
	write("app.env", "APP=billing\nSLACK_TOKEN=${secret.billing/slack-bot-token}\n")
	git("add", "app.env")
	git("commit", "-q", "-m", "billing config without the token")
	git("branch", "-D", "main")
	git("branch", "-m", "main")
	rewrite := push(git("rev-parse", "HEAD"))
	if got := findings("id=" + r.ID); len(got) != 1 || got[0].TriageStatus != "remediated" || got[0].TriageActor != "system:leaked-secret-closure" ||
		got[0].TriageEvidenceRef != "history:none;scan:"+rewrite {
		t.Fatalf("residue finding after the rewrite = %+v, want remediated by scan %s", got, rewrite)
	}

	// A branch brings the value back: recorded again, regressed.
	git("checkout", "-q", "-b", "restore")
	write("restore.env", "TOKEN="+leaked+"\n")
	git("add", "restore.env")
	git("commit", "-q", "-m", "restore the token")
	back := git("rev-parse", "HEAD")
	git("checkout", "-q", "main")
	push(git("rev-parse", "HEAD"))
	got := findings("id=" + r.ID)
	if len(got) != 1 || !got[0].Regressed || len(got[0].Metadata.HistoryResidue) != 1 || got[0].Metadata.HistoryResidue[0].Commit != back {
		t.Fatalf("residue finding once the value came back = %+v, want regressed with %s", got, back)
	}
	if h.logContains(t, leaked) {
		t.Fatal("the leaked value reached the event log")
	}
	if strings.Contains(logs.String(), leaked) {
		t.Fatal("the leaked value reached the server log")
	}
	t.Logf("P6L6_RESIDUE_FINDING_OK residue=%s closed_by=%s regressed_on=%s", r.ID, rewrite, back[:8])
}
