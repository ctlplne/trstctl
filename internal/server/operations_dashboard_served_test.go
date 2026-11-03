// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
)

// A246 Done-when: the dashboard's numbers match independent reads — the event
// log's head, the projection checkpoint, a separate count of the outbox, the
// DR posture endpoint and /readyz.
func TestServedOperationsDashboardMatchesIndependentReadsA246(t *testing.T) {
	// A real backup directory: one hashed artifact, taken thirty hours ago. It
	// verifies on every read, and it is still more than a day old.
	backupDir := t.TempDir()
	artifact := filepath.Join(backupDir, "events.jsonl")
	if err := os.WriteFile(artifact, []byte("{\"sequence\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := backup.HashFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	manifest := backup.NewFullManifest([]backup.Artifact{{Name: "events", Role: "event-log", Path: "events.jsonl",
		SHA256: sum, Bytes: size, Exists: true, Captured: true, Required: true}})
	manifest.CreatedAt = time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Second)
	if err := backup.WriteFullManifest(filepath.Join(backupDir, backup.FullManifestName), manifest); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.BackupDirectory = backupDir })
	tok := seedScopedToken(t, h.store, h.tenant, "access:read", "owners:write", "identities:read", "identities:write",
		"certs:issue", "connectors:read", "connectors:write")
	post := func(path, key string, body any) map[string]any {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, path, tok, key, body)
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("POST %s: %d %s", path, status, raw)
		}
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return out
	}
	// Some queued work: two certificates bound to a destination nobody reaches,
	// left undrained so their commands wait.
	owner := post("/api/v1/owners", "a246-owner", map[string]any{"kind": "workload", "name": "a246-dashboard"})
	for i, name := range []string{"a246-one.served.test", "a246-two.served.test"} {
		target := post("/api/v1/connectors/targets", fmt.Sprintf("a246-lb-%d", i), map[string]any{
			"name": fmt.Sprintf("a246/lb-%d", i), "connector": "f5", "enabled": true,
			"config": map[string]any{"endpoint": fmt.Sprintf("https://lb-%d-a246.invalid", i), "partition": "Common"},
		})
		request := map[string]any{"owner_id": owner["id"], "identity_name": name, "target_id": target["id"], "reason": "A246 dashboard",
			"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
		preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
		request["preview_fingerprint"] = preview["request_fingerprint"]
		post("/api/v1/lifecycle/endpoint-bindings", "a246-bind-"+name, request)
	}

	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/dashboard", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("dashboard: %d %s", status, raw)
	}
	var dash struct {
		Backup struct {
			State        string `json:"state"`
			Configured   bool   `json:"configured"`
			Verified     bool   `json:"verified"`
			LastBackupAt string `json:"last_backup_at"`
			AgeSeconds   int64  `json:"age_seconds"`
		} `json:"backup"`
		RestoreProof struct {
			State string `json:"state"`
		} `json:"restore_proof"`
		Queues struct {
			State      string `json:"state"`
			Pending    int    `json:"pending"`
			Processing int    `json:"processing"`
			Failed     int    `json:"failed"`
		} `json:"queues"`
		Signer struct {
			State   string `json:"state"`
			Healthy bool   `json:"healthy"`
		} `json:"signer"`
		DataFreshness struct {
			EventHead         uint64 `json:"event_head"`
			ProjectionApplied uint64 `json:"projection_applied"`
			LagEvents         uint64 `json:"lag_events"`
		} `json:"data_freshness"`
		Dependencies []struct {
			Name    string `json:"name"`
			Healthy bool   `json:"healthy"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatal(err)
	}

	// The queue, counted independently.
	var pending, processing, failed int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM outbox WHERE tenant_id = $1 AND status = 'pending'),
			(SELECT count(*) FROM outbox WHERE tenant_id = $1 AND status = 'processing'),
			(SELECT count(*) FROM outbox WHERE tenant_id = $1 AND status = 'failed')`, h.tenant).Scan(&pending, &processing, &failed)
	}); err != nil {
		t.Fatal(err)
	}
	if dash.Queues.Pending != pending || dash.Queues.Processing != processing || dash.Queues.Failed != failed || pending == 0 {
		t.Fatalf("the dashboard's queue %+v, an independent count pending=%d processing=%d failed=%d", dash.Queues, pending, processing, failed)
	}

	// The log head and the projection checkpoint, read directly. The read
	// model can only trail the log, and the dashboard reports both.
	head, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tail, err := h.store.ProjectionTailHealth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if dash.DataFreshness.EventHead > head || dash.DataFreshness.ProjectionApplied > tail.AppliedSequence ||
		dash.DataFreshness.EventHead < dash.DataFreshness.ProjectionApplied {
		t.Fatalf("the dashboard's freshness %+v, the log head %d, the checkpoint %d", dash.DataFreshness, head, tail.AppliedSequence)
	}

	// The DR posture endpoint says the same about backups.
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/platform/dr-posture", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("dr posture: %d %s", status, raw)
	}
	var dr struct {
		BackupConfigured bool   `json:"backup_configured"`
		Verified         bool   `json:"verified"`
		LastBackupAt     string `json:"last_backup_at"`
	}
	if err := json.Unmarshal(raw, &dr); err != nil {
		t.Fatal(err)
	}
	taken := manifest.CreatedAt.Format(time.RFC3339)
	if !dr.BackupConfigured || !dr.Verified || dr.LastBackupAt != taken ||
		dash.Backup.Configured != dr.BackupConfigured || dash.Backup.Verified != dr.Verified || dash.Backup.LastBackupAt != dr.LastBackupAt {
		t.Fatalf("the dashboard's backup %+v, the DR posture %+v, the manifest's time %s", dash.Backup, dr, taken)
	}
	// Its age is the manifest's, not the verification's: thirty hours is a
	// warning even though it verified a moment ago.
	if age := time.Duration(dash.Backup.AgeSeconds) * time.Second; dash.Backup.State != "warning" || age < 30*time.Hour || age > 30*time.Hour+5*time.Minute {
		t.Fatalf("a thirty-hour-old verified backup reads %q at age %s", dash.Backup.State, age)
	}

	// /readyz names the same dependencies with the same verdicts.
	resp, err := h.ts.Client().Get(h.ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var ready map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ready)
	checks, _ := ready["checks"].(map[string]any)
	if len(checks) == 0 {
		checks = ready
	}
	seen := 0
	for _, dep := range dash.Dependencies {
		verdict, ok := checks[dep.Name].(string)
		if !ok {
			continue
		}
		seen++
		if (verdict == "ok") != dep.Healthy {
			t.Fatalf("dependency %s: the dashboard says healthy=%v, /readyz says %q", dep.Name, dep.Healthy, verdict)
		}
		if dep.Name == "signer" && dep.Healthy != dash.Signer.Healthy {
			t.Fatalf("the signer tile %+v disagrees with its probe", dash.Signer)
		}
	}
	if seen == 0 {
		t.Fatalf("no dashboard dependency matched /readyz: %v / %+v", ready, dash.Dependencies)
	}
}
