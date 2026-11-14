// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

// P6-L7: a leak a third-party scan found in a Slack export moves into the
// vault from the operator's own copy of that export, with no history residue
// (an export has none), and closes on the same evidence as a repository's
// leak: a rotation, a consumer's read of the new version and a completed scan
// of a new export that no longer sees it. A repository checkout given for a
// third-party finding is refused, and so is a copy that does not hold the
// value. Real gitleaks; the value reaches no finding, event or log.
func TestServedThirdPartyLeakMovesFromItsExportP6L7(t *testing.T) {
	bin := requireGitleaksBinary(t)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", bin)
	logs := &p6MoveLog{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	previous := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })
	root := t.TempDir()
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.Logger = logger
		d.SecretMoveClosureInterval = time.Hour
		d.SecretScanRoots = []string{root}
	})
	operator := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read", "secrets:write")
	consumer := seedScopedTokenSubject(t, h.store, h.tenant, "deploy-bot", "secrets:read")
	leaked := sec07SlackBotToken
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	export := filepath.Join(root, "slack-export")
	write(filepath.Join(export, "channels.json"), `[{"id":"C0DEPLOY","name":"deploys"}]`)
	day := filepath.Join(export, "deploys", "2026-11-14.json")
	write(day, "[\n  {\"type\": \"message\", \"text\": \"deploying\", \"ts\": \"1731585600.000100\"},\n  {\"type\": \"message\", \"text\": \"SLACK_TOKEN="+leaked+"\", \"ts\": \"1731585650.000200\"}\n]\n")

	scan := 0
	ingest := func() string {
		t.Helper()
		scan++
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/slack/ingest", operator,
			"p6l7-ingest-"+strconv.Itoa(scan), map[string]any{"source": "p6l7-slack", "artifact_path": export, "event": "p6l7"})
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("ingest: HTTP %d %s", status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain: %v", err)
		}
		return receipt.RunID
	}
	type row struct {
		ID                string `json:"id"`
		TriageStatus      string `json:"triage_status"`
		TriageActor       string `json:"triage_actor"`
		TriageEvidenceRef string `json:"triage_evidence_ref"`
		Metadata          struct {
			Capability string `json:"capability"`
			Provider   string `json:"provider"`
			File       string `json:"file"`
			Line       int    `json:"line"`
		} `json:"metadata"`
		SecretMove *struct {
			SecretName     string            `json:"secret_name"`
			HistoryResidue []json.RawMessage `json:"history_residue"`
		} `json:"secret_move"`
	}
	findings := func(query string) []row {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?"+query, operator, nil)
		assertNoPlantedSecret(t, "findings", body)
		var page struct {
			Items []row `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("findings %s: HTTP %d %s", query, status, body)
		}
		return page.Items
	}
	move := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cli.Run(t.Context(), append([]string{"--server", h.ts.URL, "--token", operator, "--tenant", h.tenant,
			"secrets", "scans", "move"}, args...), cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr)
		assertNoPlantedSecret(t, "CLI stdout", stdout.Bytes())
		assertNoPlantedSecret(t, "CLI stderr", stderr.Bytes())
		return code, stdout.String(), stderr.String()
	}

	first := ingest()
	found := findings("kind=leaked_secret&run_id=" + first)
	if len(found) != 1 || found[0].Metadata.Capability != "CAP-SCAN-04" || found[0].Metadata.Provider != "slack" ||
		found[0].Metadata.File != "deploys/2026-11-14.json" || found[0].Metadata.Line != 3 {
		t.Fatalf("the Slack export's finding = %+v", found)
	}
	leakID := found[0].ID

	// Refused: a repository checkout for a third-party finding, and a copy of
	// the export that does not hold the value.
	if code, _, stderr := move(leakID, "--repo", export, "--name", "deploys/slack-bot-token", "--gitleaks-bin", bin); code != 1 || !strings.Contains(stderr, "--export") {
		t.Fatalf("--repo for a Slack finding = %d %q", code, stderr)
	}
	stale := filepath.Join(root, "stale-export")
	write(filepath.Join(stale, "deploys", "2026-11-14.json"), "[\n  {\"type\": \"message\", \"text\": \"deploying\"},\n  {\"type\": \"message\", \"text\": \"nothing here\"}\n]\n")
	if code, _, stderr := move(leakID, "--export", stale, "--name", "deploys/slack-bot-token", "--gitleaks-bin", bin); code != 1 || !strings.Contains(stderr, "holds no slack-bot-token value") {
		t.Fatalf("a copy without the value = %d %q", code, stderr)
	}

	// Moved from the export: stored, linked, no history residue.
	code, stdout, stderr := move(leakID, "--export", export, "--name", "deploys/slack-bot-token", "--gitleaks-bin", bin)
	if code != 0 || !strings.Contains(stdout, "${secret.deploys/slack-bot-token}") || strings.Contains(stdout, "history:") || !strings.Contains(stdout, "remove it at slack") {
		t.Fatalf("move from the export = %d: %s %s", code, stdout, stderr)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/deploys/slack-bot-token", operator, nil)
	var stored struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &stored) != nil || stored.Value != leaked || stored.Version != 1 {
		t.Fatalf("the moved secret: HTTP %d version %d (value matches: %v)", status, stored.Version, stored.Value == leaked)
	}
	if f := findings("id=" + leakID); len(f) != 1 || f[0].SecretMove == nil || f[0].SecretMove.SecretName != "deploys/slack-bot-token" || len(f[0].SecretMove.HistoryResidue) != 0 {
		t.Fatalf("the moved finding = %+v", f)
	}

	// Closed on the same evidence: rotated, read, and a new export without it.
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/deploys/slack-bot-token", operator, "p6l7-rotate",
		map[string]any{"value": "rotated-p6l7-value-not-a-token"}); status != http.StatusOK {
		t.Fatalf("rotate: HTTP %d %s", status, body)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/deploys/slack-bot-token", consumer, nil); status != http.StatusOK {
		t.Fatalf("consumer read: HTTP %d", status)
	}
	if n, err := h.srv.CloseMovedSecretFindingsOnce(t.Context()); err != nil || n != 0 {
		t.Fatalf("closed %d (%v) before a scan saw the leak gone", n, err)
	}
	write(day, "[\n  {\"type\": \"message\", \"text\": \"deploying\", \"ts\": \"1731585600.000100\"},\n  {\"type\": \"message\", \"text\": \"(message deleted)\", \"ts\": \"1731585650.000200\"}\n]\n")
	clean := ingest()
	if n, err := h.srv.CloseMovedSecretFindingsOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("closure after a clean export = %d %v, want 1", n, err)
	}
	f := findings("id=" + leakID)
	if len(f) != 1 || f[0].TriageStatus != "remediated" || f[0].TriageActor != "system:leaked-secret-closure" ||
		!strings.HasPrefix(f[0].TriageEvidenceRef, "secret:deploys/slack-bot-token@v2;read:v2;scan:"+clean) {
		t.Fatalf("closed finding = %+v", f)
	}
	if residue := findings("kind=secret_history_residue&run_id=" + clean); len(residue) != 0 {
		t.Fatalf("an export's leak opened a history-residue finding: %+v", residue)
	}
	if h.logContains(t, leaked) {
		t.Fatal("the leaked value reached the event log")
	}
	if strings.Contains(logs.String(), leaked) {
		t.Fatal("the leaked value reached the server log")
	}
	t.Logf("P6L7_EXPORT_MOVE_OK finding=%s evidence=%s", leakID, f[0].TriageEvidenceRef)
}
