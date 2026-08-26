// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedDiscoveryRunRetryPreservesFailureAndLineage is the F2 recovery
// oracle. A retry is a new event/outbox-backed run, never a rewrite of the
// original terminal evidence, and HTTP replay must not queue a second copy.
func TestServedDiscoveryRunRetryPreservesFailureAndLineage(t *testing.T) {
	h := newDiscoveryRelayHarness(t, "recovery-segment")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok,
		"discovery-recovery-source", map[string]any{
			"name": "recovery-source",
			"kind": "network",
			"config": map[string]any{
				"targets":        []string{"127.0.0.1:443"},
				"allow_loopback": true,
				"segment":        "recovery-segment",
			},
		})
	if status != http.StatusCreated {
		t.Fatalf("create recovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok,
		"discovery-recovery-original", map[string]any{"source_id": source.ID, "dry_run": true})
	if status != http.StatusCreated {
		t.Fatalf("queue original run: status %d body %s", status, body)
	}
	var original struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.CompleteDiscoveryRun(t.Context(), h.tenant, store.DiscoveryRun{
		ID: original.ID, Status: "failed", Targets: 1, Failed: 1, Error: "bounded test failure",
	}); err != nil {
		t.Fatalf("complete original as failed: %v", err)
	}

	retryPath := "/api/v1/discovery/runs/" + original.ID + "/retry"
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, retryPath, tok,
		"discovery-recovery-retry", nil)
	if status != http.StatusCreated {
		t.Fatalf("retry failed run: status %d body %s", status, body)
	}
	firstBody := append([]byte(nil), body...)
	var replacement struct {
		ID           string `json:"id"`
		SourceID     string `json:"source_id"`
		Status       string `json:"status"`
		DryRun       bool   `json:"dry_run"`
		RetryOfRunID string `json:"retry_of_run_id"`
	}
	if err := json.Unmarshal(body, &replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.ID == "" || replacement.ID == original.ID || replacement.SourceID != source.ID ||
		replacement.Status != "queued" || !replacement.DryRun || replacement.RetryOfRunID != original.ID {
		t.Fatalf("replacement = %+v, want a distinct queued dry-run with preserved lineage", replacement)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, retryPath, tok,
		"discovery-recovery-retry", nil)
	if status != http.StatusCreated || string(body) != string(firstBody) {
		t.Fatalf("idempotent replay = status %d body %s, want byte-identical %s", status, body, firstBody)
	}

	storedOriginal, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	storedReplacement, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, replacement.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedOriginal.Status != "failed" || storedOriginal.RetryOfRunID != "" {
		t.Fatalf("original failure was rewritten: %+v", storedOriginal)
	}
	if storedReplacement.RetryOfRunID != original.ID {
		t.Fatalf("stored retry lineage = %q, want %q", storedReplacement.RetryOfRunID, original.ID)
	}
	var replacementQueuedEvents int
	var replacementQueueEventID string
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type != projections.EventDiscoveryRunQueued || event.TenantID != h.tenant {
			return nil
		}
		var queued projections.DiscoveryRunQueued
		if err := json.Unmarshal(event.Data, &queued); err != nil {
			return err
		}
		if queued.ID == replacement.ID {
			replacementQueuedEvents++
			replacementQueueEventID = event.ID
			if queued.RetryOfRunID != original.ID {
				t.Fatalf("queued event retry lineage = %q, want %q", queued.RetryOfRunID, original.ID)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("replay recovery events: %v", err)
	}
	if replacementQueuedEvents != 1 || replacementQueueEventID == "" {
		t.Fatalf("replacement queued events = %d eventID=%q, want exactly one", replacementQueuedEvents, replacementQueueEventID)
	}
	var outboxRows int
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			h.tenant, replacementQueueEventID).Scan(&outboxRows)
	}); err != nil {
		t.Fatalf("read replacement outbox row: %v", err)
	}
	if outboxRows != 1 {
		t.Fatalf("replacement outbox rows = %d, want exactly one", outboxRows)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/discovery/runs/"+replacement.ID+"/retry", tok, "discovery-recovery-active", nil)
	if status != http.StatusConflict {
		t.Fatalf("retry active run: status %d body %s, want 409", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/discovery/runs/00000000-0000-4000-8000-000000000999/retry", tok, "discovery-recovery-foreign", nil)
	if status != http.StatusNotFound {
		t.Fatalf("retry inaccessible run: status %d body %s, want tenant-safe 404", status, body)
	}
}
