// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// P14-L2-O1: a finding a later run observes again at another urgent score —
// a certificate distrusted since, say — is recorded at the new score, and its
// urgent alert stays the one already raised: the re-observation no longer
// fails on the alert's key. Another destination under that key is still a
// conflict.
func TestReobservedFindingAtAnotherUrgentScoreKeepsItsFirstAlertP14L2O1(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	const (
		sourceID = "00000000-0000-4000-8000-0000000014a1"
		firstRun = "00000000-0000-4000-8000-0000000014a2"
		laterRun = "00000000-0000-4000-8000-0000000014a3"
	)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "agent", Name: "p14l2o1-host",
			Config: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		for _, run := range []string{firstRun, laterRun} {
			if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
				ID: run, TenantID: tenantA, SourceID: sourceID, Status: "running", CreatedAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	input := store.DiscoveryFinding{
		RunID: firstRun, SourceID: sourceID, Kind: "x509_certificate", Ref: "edge.p14l2o1.example.test:443",
		Provenance: "agent:filesystem", Fingerprint: "p14l2o1-fingerprint", RiskScore: 80,
		Metadata: json.RawMessage(`{"display_name":"edge certificate"}`),
	}
	first, err := orch.RecordDiscoveryFinding(ctx, tenantA, input)
	if err != nil {
		t.Fatalf("first observation: %v", err)
	}
	later := input
	later.RunID, later.RiskScore = laterRun, 95
	second, err := orch.RecordDiscoveryFinding(ctx, tenantA, later)
	if err != nil {
		t.Fatalf("the re-observation at a new urgent score: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("the re-observation is finding %s, not %s", second.ID, first.ID)
	}
	var risk int
	if err := s.SystemPool().QueryRow(ctx, `SELECT risk_score FROM discovery_findings WHERE tenant_id = $1 AND id = $2`,
		tenantA, first.ID).Scan(&risk); err != nil {
		t.Fatal(err)
	}
	if risk != 95 {
		t.Fatalf("the finding reads risk %d after the re-observation, want 95", risk)
	}
	var count int
	var payload []byte
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "urgent-risk:"+first.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		tenantA, "urgent-risk:"+first.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	if count != 1 || json.Unmarshal(payload, &alert) != nil || alert.Kind != notify.KindUrgentRisk || alert.Subject != "edge certificate" {
		t.Fatalf("urgent alerts = %d %+v, want the first one alone", count, alert)
	}

	other := store.DiscoveryFinding{
		ID: "00000000-0000-4000-8000-0000000014a9", TenantID: tenantA, RunID: laterRun, SourceID: sourceID,
		Kind: "x509_certificate", Ref: "other.p14l2o1.example.test:443", Provenance: "agent:filesystem",
		Fingerprint: "p14l2o1-other", RiskScore: 95, Metadata: json.RawMessage(`{}`), DiscoveredAt: time.Now().UTC(),
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDiscoveryFindingRecordedWithAlertTx(ctx, tx, other, "notification.elsewhere", []byte(`{"kind":"risk.urgent"}`), "urgent-risk:"+first.ID)
	})
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("another destination under the alert's key = %v, want ErrIdempotencyConflict", err)
	}
}
