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
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// p6MoveLog is a concurrency-safe server log the test reads back.
type p6MoveLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *p6MoveLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *p6MoveLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type p6Finding struct {
	ID                string `json:"id"`
	RunID             string `json:"run_id"`
	SeenCount         int    `json:"seen_count"`
	TriageStatus      string `json:"triage_status"`
	TriageActor       string `json:"triage_actor"`
	TriageReason      string `json:"triage_reason"`
	TriageEvidenceRef string `json:"triage_evidence_ref"`
	Metadata          struct {
		RuleID string `json:"rule_id"`
		File   string `json:"file"`
		Line   int    `json:"line"`
	} `json:"metadata"`
	SecretMove *struct {
		SecretName     string `json:"secret_name"`
		SecretVersion  int    `json:"secret_version"`
		Reference      string `json:"reference"`
		HistoryResidue []struct {
			RuleID string `json:"rule_id"`
			File   string `json:"file"`
			Line   int    `json:"line"`
			Commit string `json:"commit"`
		} `json:"history_residue"`
		ConsumerReadVersion int    `json:"consumer_read_version"`
		ConsumerReader      string `json:"consumer_reader"`
	} `json:"secret_move"`
}

// P6: a leaked secret a repository scan found moves into the native store from
// the CLI, and its value appears in no finding, event or log. The finding links
// to the new secret and closes only on evidence: a rotation, a consumer reading
// the rotated version and a completed scan that no longer sees the leak. A scan
// that errors is no evidence; a scan that still sees the leak keeps it open;
// the history commit that held the value stays listed after it closes. Real
// gitleaks, a real git repository and the native GitHub push hook.
func TestServedLeakedSecretMovesIntoTheStoreAndClosesOnEvidenceP6(t *testing.T) {
	bin := requireGitleaksBinary(t)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", bin)
	logs := &p6MoveLog{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	previous := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.Logger = logger
		d.SecretMoveClosureInterval = time.Hour // the test runs the closure itself
		d.SecretScanWebhooks = []config.SecretScanWebhook{{
			ID: "gh-p6", TenantID: servedTestTenant, Provider: "github",
			SecretRef: writeServedCredentialFile(t, "gh-p6-hook", "p6-move-hook-secret"),
		}}
	})
	operator := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read", "secrets:write")
	consumer := seedScopedTokenSubject(t, h.store, h.tenant, "payments-api", "secrets:read")
	leaked := sec07SlackBotToken

	// The repository: the token committed in app.env.
	origin := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", origin}, args...)...).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	writeEnv := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(origin, "app.env"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "p6@example.test")
	git("config", "user.name", "p6")
	writeEnv("APP=payments\nSLACK_TOKEN=" + leaked + "\n")
	git("add", "app.env")
	git("commit", "-q", "-m", "payments config")
	leakCommit := git("rev-parse", "HEAD")

	delivery := 0
	push := func(commit string) string {
		t.Helper()
		delivery++
		body := []byte(`{"ref":"refs/heads/main","after":"` + commit + `","deleted":false,` +
			`"repository":{"full_name":"acme/payments","clone_url":"` + origin + `"}}`)
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/scans/hooks/gh-p6", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("p6-move-%d", delivery))
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(crypto.HMACSHA256([]byte("p6-move-hook-secret"), body)))
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
	runStatus := func(runID string) string {
		t.Helper()
		var status string
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT status FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, runID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	await := func(runID string) string {
		t.Helper()
		deadline := time.Now().Add(repositoryScanWait)
		for time.Now().Before(deadline) {
			h.srv.dispatchOnce(context.Background())
			switch status := runStatus(runID); status {
			case "succeeded", "partial", "failed":
				return status
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("scan run %s never completed (status %s)", runID, runStatus(runID))
		return ""
	}
	finding := func() p6Finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=leaked_secret", operator, nil)
		assertNoPlantedSecret(t, "findings list", body)
		var page struct {
			Items []p6Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 {
			t.Fatalf("leaked-secret findings: HTTP %d %s (want exactly one)", status, body)
		}
		return page.Items[0]
	}
	closeOnce := func() int {
		t.Helper()
		n, err := h.srv.CloseMovedSecretFindingsOnce(t.Context())
		if err != nil {
			t.Fatalf("closure: %v", err)
		}
		return n
	}

	// The push is scanned by the real gitleaks: one redacted finding.
	if status := await(push(leakCommit)); status != "succeeded" {
		t.Fatalf("first scan: %s", status)
	}
	f := finding()
	if f.Metadata.RuleID != "slack-bot-token" || f.Metadata.File != "app.env" || f.Metadata.Line != 2 || f.SecretMove != nil {
		t.Fatalf("finding = %+v", f)
	}
	leakID := f.ID

	// The CLI moves it: re-found in the checkout, stored, linked.
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", operator, "--tenant", h.tenant,
		"secrets", "scans", "move", leakID, "--repo", origin, "--name", "payments/slack-bot-token", "--gitleaks-bin", bin},
		cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "${secret.payments/slack-bot-token}") {
		t.Fatalf("trstctl secrets scans move = %d: %s %s", code, stdout.String(), stderr.String())
	}
	assertNoPlantedSecret(t, "CLI stdout", stdout.Bytes())
	assertNoPlantedSecret(t, "CLI stderr", stderr.Bytes())
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/payments/slack-bot-token", operator, nil)
	var stored struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &stored) != nil || stored.Value != leaked || stored.Version != 1 {
		t.Fatalf("the moved secret: HTTP %d version %d (value matches: %v)", status, stored.Version, stored.Value == leaked)
	}
	f = finding()
	if f.ID != leakID || f.SecretMove == nil || f.SecretMove.SecretName != "payments/slack-bot-token" || f.SecretMove.SecretVersion != 1 ||
		f.SecretMove.Reference != "${secret.payments/slack-bot-token}" || len(f.SecretMove.HistoryResidue) != 1 ||
		f.SecretMove.HistoryResidue[0].Commit != leakCommit || f.SecretMove.HistoryResidue[0].File != "app.env" || f.TriageStatus == "remediated" {
		t.Fatalf("moved finding = %+v", f)
	}

	// The link names a stored version and cannot be pointed elsewhere.
	for name, tc := range map[string]struct {
		body map[string]any
		code int
	}{
		"another secret":    {map[string]any{"secret_name": "payments/other", "secret_version": 1}, http.StatusConflict},
		"a missing version": {map[string]any{"secret_name": "payments/slack-bot-token", "secret_version": 9}, http.StatusConflict},
		"a bad residue": {map[string]any{"secret_name": "payments/slack-bot-token", "secret_version": 1,
			"history_residue": []map[string]any{{"rule_id": "x", "file": "a", "line": 1, "commit": "not-a-sha"}}}, http.StatusBadRequest},
	} {
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+leakID+"/secret-move", operator, "p6-"+name, tc.body); status != tc.code {
			t.Fatalf("link with %s: HTTP %d %s, want %d", name, status, body, tc.code)
		}
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+leakID+"/secret-move", consumer, "p6-consumer",
		map[string]any{"secret_name": "payments/slack-bot-token", "secret_version": 1}); status != http.StatusForbidden {
		t.Fatalf("a secrets:read token linked a finding: HTTP %d", status)
	}

	// Not rotated: the leaked value still works, so the finding stays open.
	if n := closeOnce(); n != 0 {
		t.Fatalf("closed %d before any rotation", n)
	}
	// Rotated, but no consumer has read the new version and nothing was scanned since.
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/payments/slack-bot-token", operator, "p6-rotate",
		map[string]any{"value": "rotated-p6-value-not-a-token"}); status != http.StatusOK {
		t.Fatalf("rotate: HTTP %d %s", status, body)
	}
	if n := closeOnce(); n != 0 {
		t.Fatalf("closed %d on the rotation alone", n)
	}
	// A consumer reads the rotated version: recorded, still open.
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/payments/slack-bot-token", consumer, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"version":2`)) {
		t.Fatalf("consumer read: HTTP %d %s", status, body)
	}
	if f = finding(); f.SecretMove.ConsumerReadVersion != 2 || f.SecretMove.ConsumerReader != "payments-api" {
		t.Fatalf("consumer read not recorded: %+v", f.SecretMove)
	}
	if n := closeOnce(); n != 0 {
		t.Fatalf("closed %d with no scan since the rotation", n)
	}
	// A scan that errors (the pushed commit does not exist) is no evidence.
	failing := push(strings.Repeat("0", 40))
	for range 3 {
		h.srv.dispatchOnce(context.Background())
	}
	if status := runStatus(failing); status == "succeeded" || status == "partial" {
		t.Fatalf("a scan of a missing commit completed: %s", status)
	}
	if n := closeOnce(); n != 0 {
		t.Fatalf("closed %d on a scan that errored", n)
	}
	// A scan that still sees the leak keeps it open: the same finding, seen again
	// (its identity no longer depends on the clone's temporary directory).
	if status := await(push(leakCommit)); status != "succeeded" {
		t.Fatalf("rescan: %s", status)
	}
	if f = finding(); f.ID != leakID || f.SeenCount < 2 {
		t.Fatalf("the rescan did not see the same finding again: %+v", f)
	}
	if n := closeOnce(); n != 0 {
		t.Fatalf("closed %d while a scan still sees the leak", n)
	}

	// The value removed from the file and the clean commit scanned: it closes,
	// with its evidence, and the history commit stays listed.
	writeEnv("APP=payments\n")
	git("commit", "-q", "-am", "read the token from the secret store")
	cleanRun := push(git("rev-parse", "HEAD"))
	if status := await(cleanRun); status != "succeeded" {
		t.Fatalf("clean scan: %s", status)
	}
	if n := closeOnce(); n != 1 {
		t.Fatalf("closed %d after rotation, consumer read and a clean scan, want 1", n)
	}
	f = finding()
	if f.TriageStatus != "remediated" || f.TriageActor != "system:leaked-secret-closure" ||
		!strings.HasPrefix(f.TriageEvidenceRef, "secret:payments/slack-bot-token@v2;read:v2;scan:") ||
		!strings.Contains(f.TriageReason, "1 history commit(s) still hold the rotated value") ||
		f.SecretMove == nil || len(f.SecretMove.HistoryResidue) != 1 || f.SecretMove.HistoryResidue[0].Commit != leakCommit {
		t.Fatalf("closed finding = %+v", f)
	}
	if n := closeOnce(); n != 0 {
		t.Fatalf("closed %d again", n)
	}
	// The value is nowhere: not in the event log, not in the server log.
	if h.logContains(t, leaked) {
		t.Fatal("the leaked value reached the event log")
	}
	if strings.Contains(logs.String(), leaked) {
		t.Fatal("the leaked value reached the server log")
	}
	t.Logf("P6_MOVE_OK finding=%s evidence=%s residue=%s", leakID, f.TriageEvidenceRef, f.SecretMove.HistoryResidue[0].Commit)
}
