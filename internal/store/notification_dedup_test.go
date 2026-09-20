// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestNotificationThresholdDeliveryProjectionAndTenantScope(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	sentAt := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	rec := store.NotificationThresholdDelivery{
		TenantID: tenantA, Subject: "cn=api", ThresholdDays: 14, Channel: "Email", SentAt: sentAt,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyNotificationThresholdDeliveredTx(ctx, tx, rec)
	}); err != nil {
		t.Fatalf("project notification delivery: %v", err)
	}

	got, err := s.HasThresholdNotificationOnChannel(ctx, tenantA, "cn=api", 14, "email")
	if err != nil {
		t.Fatalf("HasThresholdNotificationOnChannel tenant A: %v", err)
	}
	if !got {
		t.Fatal("tenant A delivery missing after projection")
	}
	got, err = s.HasThresholdNotificationOnChannel(ctx, tenantA, "cn=api", 7, "email")
	if err != nil {
		t.Fatalf("HasThresholdNotificationOnChannel other threshold: %v", err)
	}
	if got {
		t.Fatal("different threshold was treated as delivered")
	}
	got, err = s.HasThresholdNotificationOnChannel(ctx, tenantA, "cn=api", 14, "slack")
	if err != nil {
		t.Fatalf("HasThresholdNotificationOnChannel other channel: %v", err)
	}
	if got {
		t.Fatal("different channel was treated as delivered")
	}
	got, err = s.HasThresholdNotificationOnChannel(ctx, tenantB, "cn=api", 14, "email")
	if err != nil {
		t.Fatalf("HasThresholdNotificationOnChannel tenant B: %v", err)
	}
	if got {
		t.Fatal("tenant B saw tenant A's delivery")
	}

	rec.SentAt = sentAt.Add(time.Minute)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyNotificationThresholdDeliveredTx(ctx, tx, rec)
	}); err != nil {
		t.Fatalf("replay notification delivery: %v", err)
	}
}
