// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestNotificationOperationAndDeliveryReceiptRebuildFromEvents(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	queuedAt := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	alert := json.RawMessage(`{"kind":"notification.channel_test","tenant_id":"` + tenantA + `","operation_id":"notification.test:rebuild","target_channel":"slack"}`)
	queuedPayload, err := json.Marshal(projections.NotificationTestQueued{
		ID: "notification.test:rebuild", RequestBinding: "rebuild-binding",
		ChannelID: "slack", Destination: "notification.test",
		EffectLane: "notification.test:channel:slack", Payload: alert,
	})
	if err != nil {
		t.Fatalf("marshal queued event: %v", err)
	}
	queued, err := log.Append(ctx, events.Event{
		ID: "notification.test.queued:rebuild", Type: projections.EventNotificationTestQueued,
		TenantID: tenantA, Time: queuedAt, Data: queuedPayload,
	})
	if err != nil {
		t.Fatalf("append queued event: %v", err)
	}
	if err := projector.Apply(ctx, queued); err != nil {
		t.Fatalf("project queued event: %v", err)
	}
	outboxID := int64(7)
	receiptPayload, err := json.Marshal(projections.NotificationDeliveryRecorded{
		ID: "notification.delivery:rebuild", Destination: "notification.test",
		NotificationKeyDigest: "key-digest", PayloadDigest: "payload-digest",
		Channel: "slack", OutboxID: &outboxID, Attempts: 1,
		DeliveredAt: queuedAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("marshal receipt event: %v", err)
	}
	receipt, err := log.Append(ctx, events.Event{
		ID: "notification.delivery.recorded:rebuild", Type: projections.EventNotificationDeliveryRecorded,
		TenantID: tenantA, Time: queuedAt.Add(time.Second), Data: receiptPayload,
	})
	if err != nil {
		t.Fatalf("append receipt event: %v", err)
	}
	if err := projector.Apply(ctx, receipt); err != nil {
		t.Fatalf("project receipt event: %v", err)
	}

	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "notification.test:rebuild"); err != nil {
		t.Fatalf("simulate outbox GC: %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild notification state: %v", err)
	}
	op, err := st.GetNotificationTestOperation(ctx, tenantA, "notification.test:rebuild")
	if err != nil {
		t.Fatalf("get rebuilt operation: %v", err)
	}
	if op.RequestBinding != "rebuild-binding" || op.ChannelID != "slack" || op.OutboxID == 0 {
		t.Fatalf("rebuilt operation = %+v", op)
	}
	got, err := st.GetNotificationDeliveryReceipt(ctx, tenantA, "notification.delivery:rebuild")
	if err != nil {
		t.Fatalf("get rebuilt receipt: %v", err)
	}
	if got.Channel != "slack" || got.PayloadDigest != "payload-digest" {
		t.Fatalf("rebuilt receipt = %+v", got)
	}
}
