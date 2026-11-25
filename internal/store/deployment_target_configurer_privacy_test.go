// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestConnectorConfigurerErasureCoversCurrentAndImmutableRevisions(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const subject = "connector-author@example.test"
	targetIDs := map[string]string{tenantA: "7cf2fa98-746e-48df-a0b7-f1535dbf047a", tenantB: "4a827efe-e9bc-40f5-9534-a49068aaf922"}
	const revisionID = "connector-author-event"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "connector privacy"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyDeploymentTargetUpsertedTx(ctx, tx, store.DeploymentTarget{
				ID: targetIDs[tenant], TenantID: tenant, Name: "edge", Type: "kemp",
				Config:       json.RawMessage(`{"endpoint":"https://kemp.example.test","token_ref":"secret://edge/token"}`),
				ConfiguredBy: subject, ConfiguredByRef: privacy.SubjectRef(tenant, subject),
				Enabled: true, EnabledSet: true,
			}, revisionID, time.Now().UTC())
		}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil || exported.Counts["read_models"] != 2 || len(exported.ReadModels) != 2 {
		t.Fatalf("connector configurer export omitted target or revision: count=%v err=%v", exported.Counts, err)
	}
	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatal(err)
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erasure.Reason = "test connector configurer erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure) }); err != nil {
		t.Fatal(err)
	}
	for _, get := range []struct {
		name string
		read func(string) (store.DeploymentTarget, error)
	}{
		{name: "current", read: func(tenant string) (store.DeploymentTarget, error) {
			return s.GetDeploymentTarget(ctx, tenant, targetIDs[tenant])
		}},
		{name: "revision", read: func(tenant string) (store.DeploymentTarget, error) {
			return s.GetDeploymentTargetRevision(ctx, tenant, targetIDs[tenant], revisionID)
		}},
	} {
		a, err := get.read(tenantA)
		if err != nil || a.ConfiguredBy != privacy.Placeholder(privacy.SubjectRef(tenantA, subject)) {
			t.Fatalf("%s retained erased configurer in tenant A: %q, %v", get.name, a.ConfiguredBy, err)
		}
		b, err := get.read(tenantB)
		if err != nil || b.ConfiguredBy != subject {
			t.Fatalf("%s changed tenant B: %q, %v", get.name, b.ConfiguredBy, err)
		}
	}
}
