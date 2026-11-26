// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestExternalObserverConfigurerErasureIsTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const subject = "observer-author@example.test"
	const id = "18000000-0000-4000-8000-0000000000e1"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "observer privacy"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyExternalObserverUpsertedTx(ctx, tx, store.ExternalObserver{
				TenantID: tenant, ID: id, Name: "privacy-observer", EventsURL: "https://observer.example.test/events",
				CredentialRef: "secret://observers/hmac", ConfiguredBy: subject,
				ConfiguredByRef: privacy.SubjectRef(tenant, subject), Enabled: true,
				UpdatedAt: time.Now().UTC(), EventSequence: 1,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil || exported.Counts["read_models"] != 1 || len(exported.ReadModels) != 1 || exported.ReadModels[0].Table != "external_observers" {
		t.Fatalf("observer configurer export: counts=%v err=%v", exported.Counts, err)
	}
	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatal(err)
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erasure.Reason = "observer configurer erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure) }); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetExternalObserver(ctx, tenantA, id)
	if err != nil || a.ConfiguredBy != privacy.Placeholder(privacy.SubjectRef(tenantA, subject)) {
		t.Fatalf("tenant A configurer: %q, %v", a.ConfiguredBy, err)
	}
	b, err := s.GetExternalObserver(ctx, tenantB, id)
	if err != nil || b.ConfiguredBy != subject {
		t.Fatalf("tenant B configurer: %q, %v", b.ConfiguredBy, err)
	}
}
