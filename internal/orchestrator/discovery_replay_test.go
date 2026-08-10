// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestRecordDiscoveryFindingRetryEmitsOneDeterministicPayloadIdentityAUD96(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	const (
		sourceID = "00000000-0000-4000-8000-000000009611"
		runID    = "00000000-0000-4000-8000-000000009612"
	)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		now := time.Date(2026, 8, 10, 7, 3, 10, 0, time.UTC)
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "manual", Name: "manual-shadow",
			Config: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "running", CreatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}

	orch := orchestrator.NewOrchestrator(log, s, nil)
	input := store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: "x509_certificate",
		Ref: "shadow-ingress.demo.trstctl.local:443", Provenance: "manual:shadow-inventory",
		Fingerprint: "demo-shadow-ingress-fingerprint", RiskScore: 82,
		Metadata: json.RawMessage(`{"action":"investigate","owner_hint":"security"}`),
	}
	first, err := orch.RecordDiscoveryFinding(ctx, tenantA, input)
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	second, err := orch.RecordDiscoveryFinding(ctx, tenantA, input)
	if err != nil {
		t.Fatalf("at-least-once retry: %v", err)
	}
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("retry finding IDs = %q then %q, want one deterministic non-empty ID", first.ID, second.ID)
	}

	var payloadIDs []string
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventDiscoveryFindingRecorded {
			return nil
		}
		var payload projections.DiscoveryFindingRecorded
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		payloadIDs = append(payloadIDs, payload.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(payloadIDs) != 2 || payloadIDs[0] != first.ID || payloadIDs[1] != first.ID {
		t.Fatalf("immutable retry payload IDs = %v, want [%s %s]", payloadIDs, first.ID, first.ID)
	}
	findings, err := s.ListDiscoveryFindingsPage(ctx, tenantA, runID, "00000000-0000-0000-0000-000000000000", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID != first.ID {
		t.Fatalf("projected findings = %+v, want one canonical row %s", findings, first.ID)
	}
}
