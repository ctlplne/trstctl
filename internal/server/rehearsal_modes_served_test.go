// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A247: a sandbox replay runs against a non-production target and never a
// production one or stored secrets; a live observation reads production's own
// signed records; a step its mode cannot run blocks the run instead of
// passing it.
func TestServedRehearsalSandboxAndLiveModesA247(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.AuditSigningKey = auditKey })
	author := seedScopedTokenSubject(t, h.store, h.tenant, "scenario-author", "incidents:read", "incidents:write", "connectors:write")
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "game-day-lead", "incidents:read", "incidents:game-day")

	target := func(key, name, environment string) string {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/connectors/targets", author, key, map[string]any{
			"name": name, "connector": "f5", "enabled": true,
			"config": map[string]any{"endpoint": "https://" + strings.ReplaceAll(name, "/", "-") + ".internal", "partition": "Common", "environment": environment},
		})
		var out struct {
			ID string `json:"id"`
		}
		if (code != http.StatusCreated && code != http.StatusOK) || json.Unmarshal(body, &out) != nil || out.ID == "" {
			t.Fatalf("create target %s = %d %s", name, code, body)
		}
		return out.ID
	}
	staging := target("a247-staging", "a247/staging-lb", "staging")
	production := target("a247-production", "a247/production-lb", "production")

	save := func(key string, scenario map[string]any) string {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/rehearsals/scenarios", author, key, scenario)
		var out struct {
			ID string `json:"id"`
		}
		if code != http.StatusCreated || json.Unmarshal(body, &out) != nil {
			t.Fatalf("save %s = %d %s", key, code, body)
		}
		return out.ID
	}
	type run struct {
		Label        string `json:"label"`
		Verdict      string `json:"verdict"`
		Detail       string `json:"detail"`
		Observations []struct {
			Effect  string `json:"effect"`
			Source  string `json:"source"`
			Receipt string `json:"receipt"`
		} `json:"observations"`
	}
	start := func(id, key, mode string) (int, run, string) {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/rehearsals/scenarios/"+id+"/runs", lead, key, map[string]any{"mode": mode})
		var out run
		if code == http.StatusCreated {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
		}
		return code, out, string(body)
	}
	retry := func(targetID string, data map[string]any) map[string]any {
		return map[string]any{
			"name": "A retried test is one effect", "kind": "retry",
			"candidate": map[string]any{"kind": "target", "ref": targetID}, "data_set": data,
			"steps": []map[string]any{{"action": "repeat_request_with_same_key", "target": targetID, "expect": "one_effect"}},
		}
	}

	// Sandbox: a staging target, through the production idempotency layer.
	code, sandbox, body := start(save("a247-retry-staging", retry(staging, map[string]any{"kind": "identities"})), "a247-run-sandbox", "sandbox_execution")
	if code != http.StatusCreated || sandbox.Label != "sandbox: matched" || len(sandbox.Observations) != 1 ||
		sandbox.Observations[0].Effect != "one_effect" || sandbox.Observations[0].Source != "sandbox_receipt" ||
		!strings.HasPrefix(sandbox.Observations[0].Receipt, "idempotency:rehearsal:") {
		t.Fatalf("sandbox retry on a staging target = %d %s", code, body)
	}

	// The guard: a production target, or a data set naming stored secrets.
	if code, _, body := start(save("a247-retry-prod", retry(production, map[string]any{"kind": "identities"})), "a247-run-prod", "sandbox_execution"); code != http.StatusUnprocessableEntity || !strings.Contains(body, "not non-production") {
		t.Fatalf("sandbox replay on a production target = %d %s", code, body)
	}
	withSecret := map[string]any{"kind": "scrubbed_failure", "failure": map[string]any{"source": "outbox_dead_letter", "ref": "dl-9"}, "secret_refs": []string{"payments/db-password"}}
	if code, _, body := start(save("a247-retry-secret", retry(staging, withSecret)), "a247-run-secret", "sandbox_execution"); code != http.StatusUnprocessableEntity || !strings.Contains(body, "stored secret") {
		t.Fatalf("sandbox replay over a stored secret = %d %s", code, body)
	}

	// A step the sandbox has no executor for blocks the run.
	outage := save("a247-outage", map[string]any{
		"name": "An unreachable load balancer", "kind": "target_outage",
		"candidate": map[string]any{"kind": "target", "ref": staging}, "data_set": map[string]any{"kind": "identities"},
		"steps": []map[string]any{{"action": "deliver_to_unreachable_target", "target": staging, "expect": "retried_with_backoff"}},
	})
	if code, blocked, body := start(outage, "a247-run-outage", "sandbox_execution"); code != http.StatusCreated || blocked.Label != "sandbox: blocked" || !strings.Contains(blocked.Detail, "no sandbox executor") {
		t.Fatalf("an unsupported sandbox step = %d %s", code, body)
	}

	// Live: the newest signed restore drill.
	restore := save("a247-restore", map[string]any{
		"name": "Restore reads back", "kind": "restore",
		"candidate": map[string]any{"kind": "binary", "ref": buildinfo.Version()}, "data_set": map[string]any{"kind": "identities"},
	})
	if code, none, body := start(restore, "a247-run-live-none", "live_observation"); code != http.StatusCreated || none.Label != "live: diverged" || none.Observations[0].Effect != "no_drill_recorded" {
		t.Fatalf("live restore with no drill = %d %s", code, body)
	}
	now := time.Now().UTC()
	evidence, err := backup.SignDrillEvidence(t.Context(), auditKey, "a247-drill", backup.DrillAttestation{
		Outcome: backup.DrillRestored, StartedAt: now.Add(-time.Minute), CompletedAt: now,
		EventsRestored: 3, EventsVerified: 3, KeysVerified: 1, SecretsVerified: 2, FullSetRestored: true,
		StoreHealthy: true, EventLogHealthy: true, SignerHealthy: true, ServerHealthy: true, Detail: "restored and read back",
	}, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.RestoreDrillRecorded{AttestationID: projections.RestoreDrillAttestationID(h.tenant, "a247-drill"), Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.log.Append(t.Context(), events.Event{ID: "a247-drill-recorded", Type: projections.EventRestoreDrillRecorded,
		TenantID: h.tenant, Time: now, SchemaVersion: 1, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(t.Context(), stored); err != nil {
		t.Fatal(err)
	}
	code, live, body := start(restore, "a247-run-live", "live_observation")
	if code != http.StatusCreated || live.Label != "live: matched" || live.Observations[0].Source != "live_receipt" ||
		!strings.HasPrefix(live.Observations[0].Receipt, "attestation:") {
		t.Fatalf("live restore = %d %s", code, body)
	}
	if code, mocked, body := start(restore, "a247-run-mocked", "mocked_rehearsal"); code != http.StatusCreated || mocked.Label != "mocked: matched" {
		t.Fatalf("mocked restore = %d %s", code, body)
	}
}
