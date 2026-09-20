// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/store"
)

// TestAUD67ServedCanonicalRiskSummaryAndAlert proves the literal contradiction
// is closed through the assembled binary: certificate risk is empty, contextual
// discovery is critical, the headline is non-zero, and the same immutable
// finding creates exactly one operator notification.
func TestAUD67ServedCanonicalRiskSummaryAndAlert(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := context.Background()
	const (
		sourceID = "00000000-0000-4000-8000-000000006721"
		runID    = "00000000-0000-4000-8000-000000006722"
		otherID  = "00000000-0000-4000-8000-000000006799"
	)
	now := time.Date(2026, 8, 13, 15, 0, 0, 0, time.UTC)
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: h.tenant, Kind: "manual", Name: "aud67-shadow",
			Config: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: h.tenant, SourceID: sourceID, Status: "running", CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed discovery authority: %v", err)
	}
	finding := store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: "token", Ref: "ci/admin-token",
		Provenance: "manual:shadow-inventory", Fingerprint: "aud67-served-fingerprint", RiskScore: 96,
		Metadata: json.RawMessage(`{"display_name":"CI admin token","owner_status":"orphaned"}`),
	}
	first, err := h.srv.orch.RecordDiscoveryFinding(ctx, h.tenant, finding)
	if err != nil {
		t.Fatalf("record critical discovery: %v", err)
	}
	if _, err := h.srv.orch.RecordDiscoveryFinding(ctx, h.tenant, finding); err != nil {
		t.Fatalf("replay critical discovery: %v", err)
	}

	token := seedScopedToken(t, h.store, h.tenant, "risk:read", "notifications:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/risk/credentials", token, nil)
	if status != http.StatusOK || string(body) != `{"credentials":[]}` {
		t.Fatalf("base credential risk = %d %s, want an honestly empty projection", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/risk/contextual-priorities", token, nil)
	if status != http.StatusOK {
		t.Fatalf("canonical risk summary = %d %s", status, body)
	}
	var riskResponse struct {
		Urgent struct {
			Status              string   `json:"status"`
			Urgent              int      `json:"urgent"`
			Critical            int      `json:"critical"`
			IncludedProjections []string `json:"included_projections"`
			CredentialRisk      struct {
				Analyzed int `json:"analyzed"`
			} `json:"credential_risk"`
			ContextualPriorities struct {
				Critical int `json:"critical"`
			} `json:"contextual_priorities"`
		} `json:"urgent_summary"`
	}
	if err := json.Unmarshal(body, &riskResponse); err != nil {
		t.Fatalf("decode canonical risk summary: %v (%s)", err, body)
	}
	if riskResponse.Urgent.Status != "complete" || riskResponse.Urgent.Urgent != 1 || riskResponse.Urgent.Critical != 1 ||
		riskResponse.Urgent.CredentialRisk.Analyzed != 0 || riskResponse.Urgent.ContextualPriorities.Critical != 1 ||
		len(riskResponse.Urgent.IncludedProjections) != 2 {
		t.Fatalf("canonical urgent summary = %+v", riskResponse.Urgent)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notifications", token, nil)
	if status != http.StatusOK {
		t.Fatalf("notification inbox = %d %s", status, body)
	}
	var inbox struct {
		Items []struct {
			Destination string `json:"destination"`
			Kind        string `json:"kind"`
			Subject     string `json:"subject"`
			Severity    string `json:"severity"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &inbox); err != nil {
		t.Fatalf("decode notification inbox: %v (%s)", err, body)
	}
	if len(inbox.Items) != 1 || inbox.Items[0].Destination != notify.DestinationRisk || inbox.Items[0].Kind != notify.KindUrgentRisk ||
		inbox.Items[0].Subject != "CI admin token" || inbox.Items[0].Severity != notify.AlertSeverityCritical {
		t.Fatalf("canonical risk inbox = %+v", inbox.Items)
	}
	var outboxCount int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		h.tenant, "urgent-risk:"+first.ID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("risk alert outbox rows after replay = %d, want 1", outboxCount)
	}

	// The exact same routes under another authenticated tenant must not see the
	// first tenant's critical projection or durable alert (AN-1).
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: otherID, Name: "Other"}); err != nil {
		t.Fatalf("create isolation tenant: %v", err)
	}
	otherToken := seedScopedToken(t, h.store, otherID, "risk:read", "notifications:read")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/risk/contextual-priorities", otherToken, nil)
	if status != http.StatusOK {
		t.Fatalf("other tenant risk summary = %d %s", status, body)
	}
	if err := json.Unmarshal(body, &riskResponse); err != nil {
		t.Fatalf("decode other tenant risk summary: %v (%s)", err, body)
	}
	if riskResponse.Urgent.Status != "complete" || riskResponse.Urgent.Urgent != 0 || riskResponse.Urgent.Critical != 0 {
		t.Fatalf("other tenant inherited urgent risk: %+v", riskResponse.Urgent)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notifications", otherToken, nil)
	if status != http.StatusOK {
		t.Fatalf("other tenant notification inbox = %d %s", status, body)
	}
	if err := json.Unmarshal(body, &inbox); err != nil {
		t.Fatalf("decode other tenant notification inbox: %v (%s)", err, body)
	}
	if len(inbox.Items) != 0 {
		t.Fatalf("other tenant inherited risk alerts: %+v", inbox.Items)
	}
}
