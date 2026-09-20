// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretscan"
)

func TestServedThirdPartySecretScanningCAPSCAN04EndToEnd(t *testing.T) {
	root := t.TempDir()
	rawSecret := "xoxb-cap-scan-04-secret-value" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	artifacts := map[string]string{
		"cicd_log":           writeSecretArtifact(t, root, "cicd-log/build.log", "CI_JOB_TOKEN="+rawSecret+"\n"),
		"container_registry": writeSecretArtifact(t, root, "registry/layer.env", "REGISTRY_PASSWORD="+rawSecret+"\n"),
		"slack":              writeSecretArtifact(t, root, "slack/export.jsonl", `{"text":"token `+rawSecret+`"}`+"\n"),
		"jira":               writeSecretArtifact(t, root, "jira/issues.jsonl", `{"description":"leaked `+rawSecret+`"}`+"\n"),
	}
	fake := &fakeThirdPartySecretScanner{called: make(chan string, len(artifacts))}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "graph:read")

	runIDs := map[string]string{}
	for provider, path := range artifacts {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/"+provider+"/ingest", tok, "cap-scan-04-"+provider, map[string]any{
			"source":        "acme/" + provider,
			"artifact_path": path,
			"artifact_kind": provider,
			"event":         "served-fixture",
		})
		if status != http.StatusAccepted {
			t.Fatalf("%s ingest status = %d, want 202; body=%s", provider, status, body)
		}
		var receipt struct {
			Capability        string `json:"capability"`
			Provider          string `json:"provider"`
			Source            string `json:"source"`
			RunID             string `json:"run_id"`
			Queued            bool   `json:"queued"`
			Status            string `json:"status"`
			OutboxDestination string `json:"outbox_destination"`
		}
		if err := json.Unmarshal(body, &receipt); err != nil {
			t.Fatalf("decode %s receipt: %v (%s)", provider, err, body)
		}
		if receipt.Capability != "CAP-SCAN-04" || receipt.Provider != provider || receipt.Source == "" || receipt.RunID == "" || !receipt.Queued || receipt.Status != "queued" || receipt.OutboxDestination != "discovery.run" {
			t.Fatalf("%s receipt = %+v, want queued CAP-SCAN-04 discovery.run", provider, receipt)
		}
		runIDs[provider] = receipt.RunID
	}

	deadline := time.After(5 * time.Second)
	for len(fake.paths()) < len(artifacts) {
		h.srv.dispatchOnce(context.Background())
		select {
		case <-fake.called:
		case <-deadline:
			t.Fatalf("third-party secret scans delivered %d/%d artifacts: %v", len(fake.paths()), len(artifacts), fake.paths())
		case <-time.After(50 * time.Millisecond):
		}
	}

	for provider, runID := range runIDs {
		findingsURL := "/api/v1/discovery/findings?run_id=" + runID
		deadline := time.After(5 * time.Second)
		var text string
		for {
			status, body := secretsReq(t, h, http.MethodGet, findingsURL, tok, nil)
			if status != http.StatusOK {
				t.Fatalf("%s findings status = %d body %s", provider, status, body)
			}
			text = string(body)
			if strings.Contains(text, `"kind":"leaked_secret"`) {
				break
			}
			select {
			case <-deadline:
				t.Fatalf("%s findings were not projected: %s", provider, body)
			case <-time.After(50 * time.Millisecond):
			}
		}
		for _, want := range []string{`"kind":"leaked_secret"`, `"capability":"CAP-SCAN-04"`, `"provider":"` + provider + `"`, "token@"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s findings missing %q: %s", provider, want, text)
			}
		}
		if strings.Contains(text, rawSecret) {
			t.Fatalf("%s findings leaked raw secret value: %s", provider, text)
		}
	}
	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event for CAP-SCAN-04 third-party scan", eventType)
		}
	}
	if h.logContains(t, rawSecret) {
		t.Fatal("CAP-SCAN-04 events leaked raw third-party secret material")
	}
}

type fakeThirdPartySecretScanner struct {
	called chan string
	mu     sync.Mutex
	seen   []string
}

func (f *fakeThirdPartySecretScanner) Scan(_ context.Context, path string) (secretscan.Report, error) {
	f.mu.Lock()
	f.seen = append(f.seen, path)
	f.mu.Unlock()
	f.called <- path
	provider := filepath.Base(filepath.Dir(path))
	if provider == "." || provider == string(filepath.Separator) {
		provider = "third-party"
	}
	return secretscan.Report{
		Scanner:       "gitleaks",
		EngineVersion: secretscan.GitleaksPinnedVersion,
		RulesActive:   secretscan.GitleaksDefaultRulesActive,
		Findings: []secretscan.Finding{{
			Scanner:       "gitleaks",
			RuleID:        provider + "-token",
			File:          filepath.Base(path),
			Line:          1,
			Fingerprint:   provider + "-fingerprint",
			CredentialRef: provider + "-token@" + filepath.Base(path),
		}},
	}, nil
}

func (f *fakeThirdPartySecretScanner) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.seen))
	copy(out, f.seen)
	return out
}

func writeSecretArtifact(t *testing.T, root, rel, body string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
