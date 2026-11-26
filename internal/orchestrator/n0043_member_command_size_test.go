// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestN0043OversizedMemberUpsertNeverLeavesPendingCrashFence(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	_, err := orch.UpsertTenantMember(ctx, tenantA, store.TenantMember{
		Subject: "oversized-member", DisplayName: strings.Repeat("<", 150000), Roles: []string{},
	})
	if err == nil {
		t.Fatal("oversized member was accepted")
	}
	pending, err := st.ListPendingTenantMemberUpsertCommands(ctx, tenantA, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("oversized upsert left %d pending crash fences: %v", len(pending), err)
	}
	if _, err := orch.ReconcilePendingTenantMemberUpserts(ctx); err != nil {
		t.Fatalf("oversized upsert blocked startup recovery: %v", err)
	}
}

func TestN0043OversizedMemberOffboardNeverLeavesPendingCrashFence(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	if _, err := orch.UpsertTenantMember(ctx, tenantA, store.TenantMember{
		Subject: "oversized-offboard", DisplayName: "ready", Roles: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := orch.OffboardTenantMember(ctx, tenantA, "oversized-offboard", strings.Repeat("<", 150000))
	if err == nil {
		t.Fatal("oversized offboard reason was accepted")
	}
	pending, err := st.ListPendingTenantMemberOffboardCommands(ctx, tenantA, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("oversized offboard left %d pending crash fences: %v", len(pending), err)
	}
	if _, err := orch.ReconcilePendingTenantMemberOffboards(ctx); err != nil {
		t.Fatalf("oversized offboard blocked startup recovery: %v", err)
	}
}

func registerN0043Tenant(t *testing.T, log *events.Log, st *store.Store, tenantID string) {
	t.Helper()
	ev, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantID, Data: []byte(`{"name":"member recovery"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
}

func TestN0043HistoricalOversizedUpsertSkipsTenantAndAllowsBoundedRetry(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	registerN0043Tenant(t, log, st, tenantA)
	registerN0043Tenant(t, log, st, tenantB)
	const subject = "legacy-oversized-upsert"
	data, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: subject, DisplayName: strings.Repeat("<", 150000), Roles: []string{}, Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := uuid.NewString()
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO tenant_member_upsert_commands
		(tenant_id, subject_ref, event_id, event_time, event_schema_version, event_payload, payload_sha256)
		VALUES ($1,$2,$3,$4,1,$5,$6)`, tenantA, privacy.SubjectRef(tenantA, subject), eventID,
		time.Now().UTC(), data, crypto.SHA256Hex(data)); err != nil {
		t.Fatal(err)
	}
	healthy := events.Event{ID: uuid.NewString(), Type: projections.EventTenantMemberUpserted,
		TenantID: tenantB, SchemaVersion: 1, Time: time.Now().UTC().Truncate(time.Microsecond),
		Data: []byte(`{"subject":"healthy-member","display_name":"ready","roles":[],"source":"manual"}`)}
	if _, _, err := st.ClaimTenantMemberUpsertCommand(ctx, tenantB, "healthy-member", healthy, false); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcilePendingTenantMemberUpserts(ctx); err != nil || healed != 1 {
		t.Fatalf("cross-tenant upsert recovery healed=%d err=%v, want one healthy command", healed, err)
	}
	var blocked string
	if err := st.SystemPool().QueryRow(ctx, `SELECT recovery_blocked_reason
		FROM tenant_member_upsert_commands WHERE tenant_id=$1 AND subject_ref=$2`,
		tenantA, privacy.SubjectRef(tenantA, subject)).Scan(&blocked); err != nil || blocked != "event_payload_too_large" {
		t.Fatalf("legacy upsert block=%q err=%v", blocked, err)
	}
	if _, err := st.GetTenantMember(ctx, tenantB, "healthy-member"); err != nil {
		t.Fatalf("later tenant member was not recovered: %v", err)
	}
	if _, err := orch.UpsertTenantMember(ctx, tenantA, store.TenantMember{
		Subject: subject, DisplayName: "bounded retry", Roles: []string{},
	}); err != nil {
		t.Fatalf("bounded retry could not replace blocked command: %v", err)
	}
	if _, found, err := log.EventByID(ctx, eventID); err != nil || found {
		t.Fatalf("old oversized event reached log: found=%v err=%v", found, err)
	}
}

func TestN0043HistoricalOversizedOffboardKeepsDenialAndAllowsBoundedRetry(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	registerN0043Tenant(t, log, st, tenantA)
	const subject = "legacy-oversized-offboard"
	if _, err := orch.UpsertTenantMember(ctx, tenantA, store.TenantMember{
		Subject: subject, DisplayName: "ready", Roles: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(projections.TenantMemberOffboarded{
		Subject: subject, Reason: strings.Repeat("<", 150000),
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := uuid.NewString()
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO tenant_member_offboard_commands
		(tenant_id, subject_ref, event_id, event_time, event_schema_version, event_payload, payload_sha256)
		VALUES ($1,$2,$3,$4,1,$5,$6)`, tenantA, privacy.SubjectRef(tenantA, subject), eventID,
		time.Now().UTC(), data, crypto.SHA256Hex(data)); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcilePendingTenantMemberOffboards(ctx); err != nil || healed != 0 {
		t.Fatalf("oversized offboard recovery healed=%d err=%v, want isolated blocked command", healed, err)
	}
	if denied, err := st.MemberOffboardStatus(ctx, tenantA, subject); err != nil || !denied {
		t.Fatalf("blocked offboard did not retain access denial: denied=%v err=%v", denied, err)
	}
	if _, _, err := orch.OffboardTenantMember(ctx, tenantA, subject, "bounded retry"); err != nil {
		t.Fatalf("bounded offboard retry could not replace blocked command: %v", err)
	}
	if _, found, err := log.EventByID(ctx, eventID); err != nil || found {
		t.Fatalf("old oversized offboard reached log: found=%v err=%v", found, err)
	}
}
