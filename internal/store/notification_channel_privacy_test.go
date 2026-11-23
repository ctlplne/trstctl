// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestNotificationConfigurerErasureIsTenantScopedAndStopsRedemption(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const subject = "channel-author@example.test"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "channel privacy"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyNotificationChannelUpsertedTx(ctx, tx, store.NotificationChannel{
				TenantID: tenant, ID: "webhook", ChannelType: "webhook", Label: "alerts",
				EndpointURL: "https://notifications.example.test/hook", CredentialRef: "secret://alerts/key",
				ConfiguredBy: subject, ConfiguredByRef: privacy.SubjectRef(tenant, subject), Enabled: true,
				CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil || exported.Counts["read_models"] != 1 || len(exported.ReadModels) != 1 || exported.ReadModels[0].Table != "notification_channels" {
		t.Fatalf("configurer export omitted channel: counts=%v err=%v", exported.Counts, err)
	}
	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatal(err)
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erasure.Reason = "test channel configurer erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure) }); err != nil {
		t.Fatal(err)
	}
	gotA, err := s.GetNotificationChannel(ctx, tenantA, "webhook")
	if err != nil || gotA.ConfiguredBy != privacy.Placeholder(privacy.SubjectRef(tenantA, subject)) {
		t.Fatalf("erased configurer remains in tenant A: subject=%q err=%v", gotA.ConfiguredBy, err)
	}
	gotB, err := s.GetNotificationChannel(ctx, tenantB, "webhook")
	if err != nil || gotB.ConfiguredBy != subject {
		t.Fatalf("tenant A erasure changed tenant B: subject=%q err=%v", gotB.ConfiguredBy, err)
	}
}
