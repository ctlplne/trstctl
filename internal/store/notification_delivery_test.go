// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestNotificationTestOperationSurvivesOutboxGCAndRejectsBindingDrift(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	// JetStream event timestamps carry nanoseconds while PostgreSQL stores this
	// projection at microsecond precision. Replay must compare the canonical
	// database instant instead of treating that expected precision loss as an
	// authenticated-command conflict.
	queuedAt := time.Date(2026, 7, 11, 12, 0, 0, 123456789, time.UTC)
	op := store.NotificationTestOperation{
		TenantID: tenantA, ID: "notification.test:durable-op",
		RequestBinding: "binding-a", ChannelID: "slack",
		Destination: "notification.test", CredentialConfigured: true, QueuedAt: queuedAt,
	}
	payload := []byte(`{"kind":"notification.channel_test","tenant_id":"` + tenantA + `","target_channel":"slack"}`)
	apply := func(candidate store.NotificationTestOperation) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyNotificationTestQueuedTx(ctx, tx, candidate,
				"notification.test:channel:slack", payload)
		})
	}
	if err := apply(op); err != nil {
		t.Fatalf("project notification test: %v", err)
	}
	got, err := s.GetNotificationTestOperation(ctx, tenantA, op.ID)
	if err != nil {
		t.Fatalf("get notification test: %v", err)
	}
	if got.OutboxID == 0 || got.RequestBinding != op.RequestBinding ||
		!got.QueuedAt.Equal(queuedAt.Truncate(time.Microsecond)) {
		t.Fatalf("projected operation = %+v", got)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantA, got.OutboxID)
		return err
	}); err != nil {
		t.Fatalf("simulate outbox GC: %v", err)
	}
	if err := apply(op); err != nil {
		t.Fatalf("exact event replay after outbox GC: %v", err)
	}
	var outboxes int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, op.ID).Scan(&outboxes)
	}); err != nil {
		t.Fatalf("count recreated outboxes: %v", err)
	}
	if outboxes != 0 {
		t.Fatalf("event replay recreated %d GC'd outboxes, want 0", outboxes)
	}

	changed := op
	changed.RequestBinding = "binding-b"
	if err := apply(changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed binding error = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := s.GetNotificationTestOperation(ctx, tenantB, op.ID); !store.IsNotFound(err) {
		t.Fatalf("tenant B operation lookup error = %v, want not found", err)
	}
}

func TestNotificationDeliveryReceiptProjectionIsTenantScopedAndImmutable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	outboxID := int64(91)
	rec := store.NotificationDeliveryReceipt{
		TenantID: tenantA, ID: "notification.delivery:receipt-a",
		Destination: "notification.ct", NotificationKeyDigest: "key-digest",
		PayloadDigest: "payload-digest", Channel: "Slack", OutboxID: &outboxID,
		Attempts: 1, DeliveredAt: time.Date(2026, 7, 11, 12, 1, 0, 0, time.UTC),
		RoutingSource: "inherited_policy", RoutingPolicyID: "policy-a", RoutingPolicyScope: "asset",
		RoutingPolicyDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	apply := func(candidate store.NotificationDeliveryReceipt) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyNotificationDeliveryRecordedTx(ctx, tx, candidate)
		})
	}
	if err := apply(rec); err != nil {
		t.Fatalf("project delivery receipt: %v", err)
	}
	got, err := s.GetNotificationDeliveryReceipt(ctx, tenantA, rec.ID)
	if err != nil {
		t.Fatalf("get delivery receipt: %v", err)
	}
	if got.Channel != "slack" || got.PayloadDigest != rec.PayloadDigest || got.RoutingPolicyID != rec.RoutingPolicyID || got.RoutingPolicyDigest != rec.RoutingPolicyDigest || got.RoutingSource != rec.RoutingSource || got.RoutingPolicyScope != rec.RoutingPolicyScope {
		t.Fatalf("projected receipt = %+v", got)
	}
	if _, err := s.GetNotificationDeliveryReceipt(ctx, tenantB, rec.ID); !store.IsNotFound(err) {
		t.Fatalf("tenant B receipt lookup error = %v, want not found", err)
	}
	changed := rec
	changed.PayloadDigest = "changed-payload"
	if err := apply(changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed receipt binding error = %v, want ErrIdempotencyConflict", err)
	}
	changed = rec
	changed.RoutingPolicyID = "later-policy"
	if err := apply(changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("rewritten historical policy error = %v, want conflict", err)
	}
	for _, query := range []struct {
		tenant, destination, key, payload string
		count                             int
	}{
		{tenantA, rec.Destination, rec.NotificationKeyDigest, rec.PayloadDigest, 1},
		{tenantB, rec.Destination, rec.NotificationKeyDigest, rec.PayloadDigest, 0},
		{tenantA, "notification.renewal_failed", rec.NotificationKeyDigest, rec.PayloadDigest, 0},
		{tenantA, rec.Destination, "other-command", rec.PayloadDigest, 0},
		{tenantA, rec.Destination, rec.NotificationKeyDigest, "other-payload", 0},
	} {
		rows, err := s.ListNotificationDeliveryReceipts(ctx, query.tenant, query.destination, query.key, query.payload)
		if err != nil || len(rows) != query.count {
			t.Fatalf("bound receipt lookup %+v returned %d: %v", query, len(rows), err)
		}
	}
}
