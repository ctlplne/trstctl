// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretscan"
)

// Q6-L4: a decoy secret's value planted in a repository is the known decoy,
// not a leak. A repository scan's finding whose line holds a live decoy's
// value names the decoy and is rated low; a finding beside it that holds any
// other secret stays a high-risk leak. The match reads the decoy's value
// without raising its read alert and keeps no value anywhere, and a retired
// decoy found again is an ordinary secret.
func TestServedRepositoryScanRecognizesAPlantedDecoyQ6L4(t *testing.T) {
	const baitValue = "trstctl-bait-9f3a7c21e8d04b6a"      // #nosec G101 -- fabricated decoy fixture; no value is real (CWE-798)
	const otherValue = "sk_live_q6l4_fixture_0d9e8f7a6b5c" // #nosec G101 -- fabricated fixture; no value is real (CWE-798)
	repo := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("app.env", "# payments\nPAYMENTS_API_KEY="+baitValue+"\nREGION=eu\n")
	write("ci.env", "DEPLOY_TOKEN="+otherValue+"\n")
	fake := &fakeSecretRepoScanner{called: make(chan string, 4), report: secretscan.Report{
		Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
		Findings: []secretscan.Finding{
			{Scanner: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(repo, "app.env"), Line: 2,
				Fingerprint: "q6l4-app", CredentialRef: "generic-api-key@app.env"},
			{Scanner: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(repo, "ci.env"), Line: 1,
				Fingerprint: "q6l4-ci", CredentialRef: "generic-api-key@ci.env"},
		},
	}}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "graph:read")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "q6l4-bait",
		map[string]any{"name": "q6l4/payments-api-key", "value": baitValue}); status != http.StatusCreated {
		t.Fatalf("store the bait: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", tok, "q6l4-register",
		map[string]any{"secret_name": "q6l4/payments-api-key", "name": "payments-repo-lure", "placement": "acme/payments app.env"}) // #nosec G101 -- a decoy's path and label, no credential value (CWE-798)
	var decoy struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &decoy) != nil || decoy.ID == "" {
		t.Fatalf("register the decoy: %d %s", status, body)
	}

	type finding struct {
		Ref       string `json:"ref"`
		RiskScore int    `json:"risk_score"`
		Metadata  struct {
			KnownDecoy *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"known_decoy"`
		} `json:"metadata"`
	}
	scan := func(key string) map[string]finding {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/github/webhook", tok, key, map[string]any{
			"repository": "acme/payments", "checkout_path": repo, "ref": "refs/heads/main", "commit_sha": "q6l4" + key, "event": "push",
		})
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("scan %s: %d %s", key, status, body)
		}
		deadline := time.After(repositoryScanWait)
		for done := false; !done; {
			h.srv.dispatchOnce(context.Background())
			select {
			case <-fake.called:
				done = true
			case <-deadline:
				t.Fatalf("scan %s was not delivered", key)
			case <-time.After(50 * time.Millisecond):
			}
		}
		for {
			status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, tok, nil)
			if status != http.StatusOK {
				t.Fatalf("findings: %d %s", status, body)
			}
			for _, value := range []string{baitValue, otherValue} {
				if strings.Contains(string(body), value) {
					t.Fatalf("a scanned value reached the findings: %s", body)
				}
			}
			var listed struct {
				Items []finding `json:"items"`
			}
			if err := json.Unmarshal(body, &listed); err != nil {
				t.Fatal(err)
			}
			if len(listed.Items) == 2 {
				out := map[string]finding{}
				for _, f := range listed.Items {
					out[f.Ref] = f
				}
				return out
			}
			select {
			case <-deadline:
				t.Fatalf("scan %s findings: %s", key, body)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	got := scan("q6l4-first")
	planted, other := got["generic-api-key@app.env"], got["generic-api-key@ci.env"]
	if planted.Metadata.KnownDecoy == nil || planted.Metadata.KnownDecoy.ID != decoy.ID ||
		planted.Metadata.KnownDecoy.Name != "payments-repo-lure" || planted.RiskScore != secretscan.KnownDecoyRiskScore {
		t.Fatalf("the planted decoy's finding: %+v", planted)
	}
	if other.Metadata.KnownDecoy != nil || other.RiskScore != 95 {
		t.Fatalf("the other secret's finding: %+v", other)
	}
	// Comparing the decoy's value is trstctl's own work, not a read: the
	// decoy is still unread and raised no alert.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/secrets/"+decoy.ID, tok, nil)
	var after struct {
		State       string     `json:"state"`
		TriggeredAt *time.Time `json:"triggered_at"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &after) != nil || after.State != "active" || after.TriggeredAt != nil {
		t.Fatalf("the decoy after the scan: %d %s", status, body)
	}
	var alerts int
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`, h.tenant).Scan(&alerts)
	}); err != nil || alerts != 0 {
		t.Fatalf("decoy alerts after the scan = %d, %v", alerts, err)
	}

	// A retired decoy is no longer bait: found again, it is a leak.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets/"+decoy.ID+"/retire", tok, "q6l4-retire", nil); status != http.StatusOK {
		t.Fatalf("retire: %d %s", status, body)
	}
	got = scan("q6l4-after-retire")
	if again := got["generic-api-key@app.env"]; again.Metadata.KnownDecoy != nil || again.RiskScore != 95 {
		t.Fatalf("the retired decoy's value found again: %+v", again)
	}
}
