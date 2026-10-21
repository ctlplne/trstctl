// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/privacy"
)

// Artifact retention is automated at both ends: an ingest can ask trstctl to
// remove the operator's export once the scan is terminal, and the redacted
// findings a third-party scan produced age out through the privacy retention
// worker under their own window, so a leaked-secret location does not live in
// the database forever.
func TestServedThirdPartySecretScanRetention(t *testing.T) {
	root := t.TempDir()
	artifact := writeSecretArtifact(t, root, "slack/export.jsonl", `{"text":"xoxb-retention-fixture-value"}`+"\n") // #nosec G101 -- fabricated fixture (CWE-798)
	fake := &fakeThirdPartySecretScanner{called: make(chan string, 4)}
	policy := privacy.DefaultRetentionPolicy()
	policy.ThirdPartyScanFindingsAfter = 24 * time.Hour
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
		d.PrivacyRetentionEnabled = true
		d.PrivacyRetentionPolicy = policy
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "privacy:read", "privacy:write")

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/slack/ingest", tok, "retention-1",
		map[string]any{"source": "acme/slack", "artifact_path": artifact, "delete_artifact_after_scan": true})
	if status != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", status, raw)
	}
	var receipt struct {
		RunID string `json:"run_id"`
	}
	_ = json.Unmarshal(raw, &receipt)
	deadline := time.After(5 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		code, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+receipt.RunID, tok, nil)
		if code != http.StatusOK {
			t.Fatalf("run: %d %s", code, body)
		}
		var run struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal(body, &run)
		if run.Status == "succeeded" {
			if !strings.Contains(run.Error, "artifact removed after scan") {
				t.Fatalf("run message does not record the artifact removal: %q", run.Error)
			}
			break
		}
		if run.Status == "partial" || run.Status == "failed" {
			t.Fatalf("run ended %s: %s", run.Status, run.Error)
		}
		select {
		case <-deadline:
			t.Fatalf("run did not finish: %s", body)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Fatalf("artifact still present after a scan that asked for removal: %v", err)
	}

	findings := func() string {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, tok, nil)
		if code != http.StatusOK {
			t.Fatalf("findings: %d %s", code, body)
		}
		return string(body)
	}
	deadline = time.After(5 * time.Second)
	for !strings.Contains(findings(), `"leaked_secret"`) {
		select {
		case <-deadline:
			t.Fatalf("no leaked_secret finding projected: %s", findings())
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Fresh findings survive a retention pass; findings older than the window go.
	if _, err := h.srv.RunPrivacyRetentionOnce(context.Background()); err != nil {
		t.Fatalf("retention (fresh): %v", err)
	}
	if !strings.Contains(findings(), `"leaked_secret"`) {
		t.Fatal("retention removed a finding inside its window")
	}
	if _, err := h.store.SystemPool().Exec(context.Background(),
		`UPDATE discovery_findings SET discovered_at = now() - interval '3 days' WHERE tenant_id = $1 AND run_id = $2`,
		h.tenant, receipt.RunID); err != nil {
		t.Fatalf("backdate findings: %v", err)
	}
	if _, err := h.srv.RunPrivacyRetentionOnce(context.Background()); err != nil {
		t.Fatalf("retention (aged): %v", err)
	}
	if body := findings(); strings.Contains(body, `"leaked_secret"`) {
		t.Fatalf("aged third-party findings survived retention: %s", body)
	}
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/privacy/retention-runs?limit=10", tok, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"third_party_scan_findings":1`) || !strings.Contains(string(body), `"third_party_scan_findings_before"`) {
		t.Fatalf("retention evidence lacks the third-party finding count/cutoff: %d %s", code, body)
	}
}
