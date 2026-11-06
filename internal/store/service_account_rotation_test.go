// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func seedDependentRotation(t *testing.T, s *store.Store, tenant string) servicedependents.RotationIntent {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC()
	if e := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Owned rotation"}); e != nil {
		t.Fatal(e)
	}
	account := servicedependents.AccountBinding{AccountID: googleuuid.NewString(), ProviderID: "owned-directory", Name: "svc", DN: "CN=svc,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1001", GUID: strings.Repeat("a", 32)}
	agent := googleuuid.NewString()
	binding := servicedependents.HostBinding{Account: account, AgentID: agent, Revision: 7, Enabled: true}
	intent, e := servicedependents.NewInventoryIntent(googleuuid.NewString(), binding)
	if e != nil {
		t.Fatal(e)
	}
	report := servicedependents.InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: now, Coverage: []servicedependents.FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}}, Services: []windependents.Service{{Name: "owned-work", AccountSID: account.SID, ConfigSHA256: strings.Repeat("b", 64), WasRunning: true}}}
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	digest := crypto.SHA256Hex(raw)
	if e = s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		if e := s.ApplyServiceDependentHostSavedTx(ctx, tx, tenant, account, agent, true, "owned-operator", now, 7); e != nil {
			return e
		}
		if e := s.ApplyServiceDependentScanQueuedTx(ctx, tx, tenant, intent.RunID, intent, "owned-operator", now); e != nil {
			return e
		}
		return s.ApplyServiceDependentScanObservedTx(ctx, tx, tenant, 1, 1, report, digest, "owned signed statement", "c2ln", strings.Repeat("c", 64), now)
	}); e != nil {
		t.Fatal(e)
	}
	inputs := []servicedependents.RotationHostInput{{Binding: binding, Inventory: report, InventoryDigest: digest}}
	ref := servicedependents.DependentRef{AgentID: agent, Family: "services", Name: "owned-work"}
	plan, e := servicedependents.NewRotationPlan(googleuuid.NewString(), account, "app/credential", inputs, []servicedependents.DependentRef{ref}, now)
	if e != nil {
		t.Fatal(e)
	}
	return servicedependents.RotationIntent{Plan: plan, ProviderBinding: strings.Repeat("d", 64), ExpectedVersion: 2, Probes: []servicedependents.ProbeBinding{{Ref: ref, ProbeID: "owned-work"}}}
}
func TestDependentRotationSourceAndStepTransactionsA267(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	intent := seedDependentRotation(t, s, tenantA)
	digest, e := intent.Digest()
	if e != nil {
		t.Fatal(e)
	}
	parent := store.ServiceDependentRotation{TenantID: tenantA, ID: intent.Plan.ID, Intent: intent, IntentDigest: digest, CommandID: intent.Plan.ID, TenantEpoch: "owned-epoch", Direction: servicedependents.Forward, Actor: "owned-operator", CreatedAt: intent.Plan.CreatedAt}
	injected := errors.New("owned transaction interruption")
	e = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if e := s.ApplyServiceDependentRotationQueuedTx(ctx, tx, parent); e != nil {
			return e
		}
		return injected
	})
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	if _, e = s.GetServiceDependentRotation(ctx, tenantA, parent.ID); !errors.Is(e, store.ErrServiceDependentRotationNotFound) {
		t.Fatal("aborted transaction retained parent", e)
	}
	if e = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyServiceDependentRotationQueuedTx(ctx, tx, parent) }); e != nil {
		t.Fatal(e)
	}
	got, e := s.GetServiceDependentRotation(ctx, tenantA, parent.ID)
	if e != nil || got.IntentDigest != digest {
		t.Fatal("retained parent differs", e)
	}
	if _, e = s.GetServiceDependentRotation(ctx, tenantB, parent.ID); !errors.Is(e, store.ErrServiceDependentRotationNotFound) {
		t.Fatal("foreign tenant read parent", e)
	}
	// A new selected host invalidates the entire frozen host set, even when the
	// requester keeps every formerly selected object and its old signed scan.
	e = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyServiceDependentHostSavedTx(ctx, tx, tenantA, intent.Plan.Account, "57200000-0000-4000-8000-000000000006", true, "owned-operator", time.Now().UTC(), 8)
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ValidateServiceDependentRotationSourcesTx(ctx, tx, tenantA, intent, true)
	}); e == nil {
		t.Fatal("new enabled host was silently omitted")
	}
}

func TestDependentRotationActorPrivacyA267(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const actor = "rotation-operator@example.test"
	var parents []store.ServiceDependentRotation
	for _, tenant := range []string{tenantA, tenantB} {
		intent := seedDependentRotation(t, s, tenant)
		digest, e := intent.Digest()
		if e != nil {
			t.Fatal(e)
		}
		parent := store.ServiceDependentRotation{TenantID: tenant, ID: intent.Plan.ID, Intent: intent, IntentDigest: digest, CommandID: intent.Plan.ID, TenantEpoch: "owned-epoch", Direction: servicedependents.Forward, Actor: actor, CreatedAt: intent.Plan.CreatedAt}
		if e = s.WithTenant(ctx, tenant, func(tx pgx.Tx) error { return s.ApplyServiceDependentRotationQueuedTx(ctx, tx, parent) }); e != nil {
			t.Fatal(e)
		}
		parents = append(parents, parent)
	}
	exported, e := s.SelectPrivacySubjectExport(ctx, tenantA, actor)
	if e != nil || exported.Counts["service_account_rotations"] != 1 {
		t.Fatal("rotation actor missing from subject export", exported.Counts, e)
	}
	erasure, e := s.SelectPrivacySubjectErasure(ctx, tenantA, actor)
	if e != nil {
		t.Fatal(e)
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erasure.Reason = "owned actor erasure"
	if e = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure) }); e != nil {
		t.Fatal(e)
	}
	// Replaying the same queued source must leave the erased actor pseudonymized.
	if e = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyServiceDependentRotationQueuedTx(ctx, tx, parents[0]) }); e != nil {
		t.Fatal(e)
	}
	for _, parent := range parents {
		got, e := s.GetServiceDependentRotation(ctx, parent.TenantID, parent.ID)
		if e != nil {
			t.Fatal(e)
		}
		want := actor
		if parent.TenantID == tenantA {
			want = privacy.Placeholder(privacy.SubjectRef(tenantA, actor))
		}
		if got.Actor != want || got.IntentDigest != parent.IntentDigest || got.CommandID != parent.CommandID {
			t.Fatal("actor erasure lost native authority, resurrected an actor or affected another tenant")
		}
	}
	// Pending rotations retain an accountable actor; terminal commands permit the
	// configured retention cutoff without changing the native evidence.
	at := time.Now().UTC().Add(400 * 24 * time.Hour)
	pending, e := s.SelectPrivacyRetention(ctx, tenantB, "57200000-0000-4000-8000-000000000007", privacy.DefaultRetentionPolicy(), at)
	if e != nil || pending.Counts["service_account_rotations"] != 0 {
		t.Fatal("pending rotation actor retention differs", pending.Counts, e)
	}
	// A completed command is operationally retained separately from its human actor.
	if e = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO secret_static_rotation_commands(tenant_id,id,tenant_epoch,provider,secret_key,expected_version,old_ref,phase,idempotency_key_digest,request_binding,created_at,updated_at,terminal_at) VALUES($1,$2,'owned-epoch','owned-directory','app/credential',2,'native','completed','owned-idempotency','owned-request',now(),now(),now())`, tenantB, parents[1].CommandID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	retained, e := s.SelectPrivacyRetention(ctx, tenantB, "57200000-0000-4000-8000-000000000008", privacy.DefaultRetentionPolicy(), at)
	if e != nil || retained.Counts["service_account_rotations"] != 1 {
		t.Fatal("terminal rotation actor retention missing", retained.Counts, e)
	}
	retained.RequestedByRef = privacy.SubjectRef(tenantB, "privacy-operator")
	if e = s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, retained) }); e != nil {
		t.Fatal(e)
	}
	got, e := s.GetServiceDependentRotation(ctx, tenantB, parents[1].ID)
	if e != nil || !strings.HasPrefix(got.Actor, "retained:") || got.IntentDigest != parents[1].IntentDigest {
		t.Fatal("retention changed native authority or retained human identity", e)
	}
}
