// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestConnectorDeliveryReceiverDeduplicatesExactAgentResult(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	outboxID := int64(41)
	identityID := "33333333-3333-4333-8333-333333333333"
	receipt := store.ConnectorDeliveryReceipt{
		ID: "44444444-4444-4444-8444-444444444444", OutboxID: &outboxID, IdentityID: &identityID,
		Destination: "connector.deploy", Connector: "nginx", Target: "edge-a",
		Fingerprint: "sha256:public-leaf", Status: "delivered", Attempts: 1,
		Reason: "agent_delivered", Detail: "delivered by enrolled agent host-a",
		RollbackRef: "restore previous certificate for edge-a", IdempotencyKey: "deploy-edge-a",
	}
	const eventID = "55555555-5555-4555-8555-555555555555"
	first, err := orch.RecordConnectorDeliveryWithEventID(ctx, tenantA, eventID, receipt)
	if err != nil {
		t.Fatalf("first connector delivery result: %v", err)
	}
	second, err := orch.RecordConnectorDeliveryWithEventID(ctx, tenantA, eventID, receipt)
	if err != nil {
		t.Fatalf("exact connector delivery replay: %v", err)
	}
	if first.ID != receipt.ID || second.ID != receipt.ID || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("exact replay changed receipt authority: first=%+v second=%+v", first, second)
	}

	eventCount := 0
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.ID == eventID && event.Type == projections.EventConnectorDeliveryRecorded && event.TenantID == tenantA {
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay connector delivery events: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("exact result replay retained %d immutable events, want one", eventCount)
	}

	changed := receipt
	changed.Target = "edge-b"
	if _, err := orch.RecordConnectorDeliveryWithEventID(ctx, tenantA, eventID, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed result replay error=%v, want idempotency conflict", err)
	}
	rows, err := st.ListConnectorDeliveryReceiptsPage(ctx, tenantA, "", store.ZeroUUID, 10)
	if err != nil || len(rows) != 1 || rows[0].Target != receipt.Target || rows[0].ID != receipt.ID {
		t.Fatalf("projected connector delivery after replay/conflict = %+v, err=%v", rows, err)
	}
}
