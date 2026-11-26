// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestHistoricalAgentInventoryDuplicateDoesNotBlockOtherTenant(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	appendAUD96DiscoveryBase(t, log)
	first := mustAppendDiscoveryFindingAUD96(t, log, aud96EarlierFinding, time.Now().UTC(), 20, `{"owner":"first"}`)
	mustAppendDiscoveryFindingAUD96(t, log, aud96EarlierFinding, time.Now().UTC(), 90, `{"owner":"changed"}`)
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegistered("Healthy")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "later owner")})
	p := projections.New(s)
	for _, run := range []struct {
		name string
		fn   func(context.Context, *events.Log) error
	}{{"catch-up", p.ProjectCatchUp}, {"rebuild", p.Rebuild}} {
		if err := run.fn(ctx, log); err != nil {
			t.Fatalf("%s blocked by historical duplicate: %v", run.name, err)
		}
		if n := ownerCount(t, s, tenantB); n != 1 {
			t.Fatalf("%s healthy owner count = %d", run.name, n)
		}
		finding, err := s.GetDiscoveryFinding(ctx, tenantA, aud96EarlierFinding)
		if err != nil || string(finding.Metadata) != `{"owner": "first"}` && string(finding.Metadata) != `{"owner":"first"}` {
			t.Fatalf("%s changed first finding from seq %d: %+v err=%v", run.name, first.Sequence, finding, err)
		}
		var riskAlerts int
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND idempotency_key LIKE 'urgent-risk:%'`, tenantA).Scan(&riskAlerts)
		}); err != nil || riskAlerts != 0 {
			t.Fatalf("%s queued alert for ignored risk score: count=%d err=%v", run.name, riskAlerts, err)
		}
	}
}

func TestHistoricalOversizedFindingQuarantinesOnlyItsTenant(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	appendAUD96DiscoveryBase(t, log)
	mustAppend(t, log, events.Event{Type: projections.EventDiscoveryFindingRecorded, TenantID: tenantA,
		Data: mustJSONAUD96(t, projections.DiscoveryFindingRecorded{
			ID: aud96EarlierFinding, RunID: aud96RunID, SourceID: aud96SourceID,
			Kind: "api_key", Ref: strings.Repeat("r", 2401), Provenance: "old-agent", Metadata: json.RawMessage(`{}`),
		})})
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegistered("Healthy")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "later owner")})
	p := projections.New(s)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("oversized finding blocked catch-up: %v", err)
	}
	if n := ownerCount(t, s, tenantB); n != 1 {
		t.Fatalf("healthy owner count = %d", n)
	}
	if quarantined, err := s.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("oversized finding quarantine=%v err=%v", quarantined, err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("oversized finding blocked rebuild: %v", err)
	}
}
