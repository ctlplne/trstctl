// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestServiceDependentInventoryActorPrivacyA267(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const actor = "inventory-operator@example.test"
	const account = "56900000-0000-4000-8000-000000000001"
	const agent = "56900000-0000-4000-8000-000000000002"
	const run = "56900000-0000-4000-8000-000000000003"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Owned inventory"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO service_account_hosts(tenant_id,account_id,agent_id,binding,revision,enabled,saved_by,updated_at) VALUES($1,$2,$3,'{"sid":"S-1-5-21-1-2-3-1001"}',7,true,$4,now())`, tenant, account, agent, actor)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO service_account_host_scans(tenant_id,id,account_id,agent_id,intent,binding_digest,status,queued_by,queued_at,queued_event_id) VALUES($1,$2,$3,$4,'{"native":"exact"}',$5,'queued',$6,now(),$2)`, tenant, run, account, agent, strings.Repeat("a", 64), actor)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, actor)
	if err != nil || exported.Counts["service_account_hosts"] != 1 || exported.Counts["service_account_host_scans"] != 1 {
		t.Fatal("inventory actors missing from subject export", exported.Counts, err)
	}
	erased, err := s.SelectPrivacySubjectErasure(ctx, tenantA, actor)
	if err != nil {
		t.Fatal(err)
	}
	erased.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erased.Reason = "owned actor erasure"
	if err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erased) }); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		if err = s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			var saved, queued, binding, intent string
			err := tx.QueryRow(ctx, `SELECT h.saved_by,s.queued_by,h.binding::text,s.intent::text FROM service_account_hosts h JOIN service_account_host_scans s ON s.tenant_id=h.tenant_id AND s.account_id=h.account_id AND s.agent_id=h.agent_id WHERE h.tenant_id=$1 AND s.tenant_id=$1 AND s.id=$2`, tenant, run).Scan(&saved, &queued, &binding, &intent)
			if err != nil {
				return err
			}
			want := actor
			if tenant == tenantA {
				want = privacy.Placeholder(privacy.SubjectRef(tenant, actor))
			}
			if saved != want || queued != want || !strings.Contains(binding, "S-1-5-21-1-2-3-1001") || !strings.Contains(intent, "exact") {
				t.Fatal("actor erasure changed native authority or foreign actor", saved, queued, binding, intent)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	runRetention, err := s.SelectPrivacyRetention(ctx, tenantB, run, privacy.DefaultRetentionPolicy(), time.Now().UTC().Add(400*24*time.Hour))
	if err != nil || runRetention.Counts["service_account_hosts"] != 1 {
		t.Fatal("host actor retention missing", runRetention.Counts, err)
	}
	runRetention.RequestedByRef = privacy.SubjectRef(tenantB, "privacy-operator")
	if err = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, runRetention) }); err != nil {
		t.Fatal(err)
	}
	if err = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		var selected, requested, binding string
		err := tx.QueryRow(ctx, `SELECT h.saved_by,s.queued_by,h.binding::text FROM service_account_hosts h JOIN service_account_host_scans s ON s.tenant_id=h.tenant_id AND s.account_id=h.account_id AND s.agent_id=h.agent_id WHERE h.tenant_id=$1 AND s.tenant_id=$1 AND s.id=$2`, tenantB, run).Scan(&selected, &requested, &binding)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(selected, "retained:") || requested != actor || !strings.Contains(binding, "S-1-5-21-1-2-3-1001") {
			t.Fatal("retention lost authority or rewrote a pending requester")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE service_account_host_scans SET status='partial' WHERE tenant_id=$1 AND id=$2`, tenantB, run)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	terminalRetention, err := s.SelectPrivacyRetention(ctx, tenantB, "56900000-0000-4000-8000-000000000004", privacy.DefaultRetentionPolicy(), time.Now().UTC().Add(400*24*time.Hour))
	if err != nil || terminalRetention.Counts["service_account_host_scans"] != 1 {
		t.Fatal("terminal scan actor retention missing", terminalRetention.Counts, err)
	}
	terminalRetention.RequestedByRef = privacy.SubjectRef(tenantB, "privacy-operator")
	if err = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, terminalRetention) }); err != nil {
		t.Fatal(err)
	}
	if err = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		var actorAfter, intent string
		err := tx.QueryRow(ctx, `SELECT queued_by,intent::text FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2`, tenantB, run).Scan(&actorAfter, &intent)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(actorAfter, "retained:") || !strings.Contains(intent, "exact") {
			t.Fatal("terminal retention changed native authority or retained raw actor")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

}
