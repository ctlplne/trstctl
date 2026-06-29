package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretscan"
)

func TestServedRepositorySecretScanWebhookQueuesAndExecutesCAPSCAN01(t *testing.T) {
	repo := t.TempDir()
	fake := &fakeSecretRepoScanner{
		called: make(chan string, 1),
		report: secretscan.Report{
			Scanner:       "gitleaks",
			EngineVersion: secretscan.GitleaksPinnedVersion,
			RulesActive:   secretscan.GitleaksDefaultRulesActive,
			Findings: []secretscan.Finding{{
				Scanner:       "gitleaks",
				RuleID:        "generic-api-key",
				File:          filepath.Join(repo, "app.env"),
				Line:          7,
				Fingerprint:   "repo-fingerprint",
				CredentialRef: "generic-api-key@app.env",
			}},
		},
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "graph:read")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/github/webhook", tok, "cap-scan-01-webhook", map[string]any{
		"repository":    "acme/payments",
		"checkout_path": repo,
		"ref":           "refs/heads/main",
		"commit_sha":    "abc123",
		"event":         "push",
	})
	if status != http.StatusAccepted {
		t.Fatalf("repository webhook status = %d, want 202; body=%s", status, body)
	}
	var receipt struct {
		Capability        string `json:"capability"`
		Provider          string `json:"provider"`
		RunID             string `json:"run_id"`
		Queued            bool   `json:"queued"`
		Status            string `json:"status"`
		OutboxDestination string `json:"outbox_destination"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatalf("decode webhook receipt: %v (%s)", err, body)
	}
	if receipt.Capability != "CAP-SCAN-01" || receipt.Provider != "github" || receipt.RunID == "" || !receipt.Queued || receipt.Status != "queued" || receipt.OutboxDestination != "discovery.run" {
		t.Fatalf("receipt = %+v, want queued CAP-SCAN-01 discovery.run", receipt)
	}

	var scannedPath string
	deadline := time.After(5 * time.Second)
	for scannedPath == "" {
		h.srv.dispatchOnce(context.Background())
		select {
		case scannedPath = <-fake.called:
		case <-deadline:
			t.Fatal("repository scan outbox row was not delivered")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if scannedPath != repo {
		t.Fatalf("scanner target = %q, want checkout path %q", scannedPath, repo)
	}
	findingsURL := "/api/v1/discovery/findings?run_id=" + receipt.RunID
	deadline = time.After(5 * time.Second)
	for {
		status, body = secretsReq(t, h, http.MethodGet, findingsURL, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("list repository scan findings: status %d body %s", status, body)
		}
		if strings.Contains(string(body), "abc123-secret-value") {
			t.Fatalf("repository scan discovery findings leaked secret data: %s", body)
		}
		if strings.Contains(string(body), `"kind":"leaked_secret"`) && strings.Contains(string(body), "generic-api-key@app.env") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("repository scan discovery findings are missing: %s", body)
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event for CAP-SCAN-01 repository scan", eventType)
		}
	}
}

type fakeSecretRepoScanner struct {
	report secretscan.Report
	called chan string
}

func (f *fakeSecretRepoScanner) Scan(_ context.Context, path string) (secretscan.Report, error) {
	f.called <- path
	return f.report, nil
}
