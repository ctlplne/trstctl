// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestServedOutboxRecoveryDoesNotResurrectErasedTenant(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	_, err := h.srv.orch.RequestServiceNowTicket(ctx, h.tenant, orchestrator.ServiceNowTicketRequest{InstanceURL: "https://owned.example.test", TokenRef: filepath.Join(t.TempDir(), "servicenow-reference"), ShortDescription: "owned retained ticket"})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := h.store.OutboxReconciliationCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error {
		_, err := h.srv.orch.ReconcileOutbox(ctx, h.log)
		if !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Errorf("replay during lifecycle operation = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if after, err := h.store.OutboxReconciliationCheckpoint(ctx); err != nil || after != checkpoint {
		t.Fatalf("busy recovery advanced checkpoint: %d -> %d (%v)", checkpoint, after, err)
	}
	offboardServedTestTenant(t, h)
	if n, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || n != 0 {
		t.Errorf("deleted tenant recovery: healed=%d err=%v", n, err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1`, h.tenant).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("startup replay recreated %d erased-tenant intents", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Reusing the UUID is a new registration, not authority for the old ticket.
	registerServedTenant(t, h, "Replacement registration")
	current, err := h.srv.orch.RequestServiceNowTicket(ctx, h.tenant, orchestrator.ServiceNowTicketRequest{InstanceURL: "https://owned.example.test", TokenRef: "current-token-reference", ShortDescription: "current registration ticket"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, current.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE outbox_reconciliation_checkpoint SET reconciled_seq=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if n, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || n != 1 {
		t.Fatalf("new registration recovery: healed=%d err=%v", n, err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1`, h.tenant).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("new registration inherited old work: %d rows", n)
		}
		var key string
		if err := tx.QueryRow(ctx, `SELECT idempotency_key FROM outbox WHERE tenant_id=$1`, h.tenant).Scan(&key); err != nil {
			return err
		}
		if key != current.IdempotencyKey {
			t.Errorf("recovered different registration intent: %s", key)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServedSuspendedMigrationRecoveryPreservesIntentWithoutService(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	runID, agentID := uuid.NewString(), uuid.NewString()
	run, actions, err := migration.StartRun(migration.Run{ID: runID, Waves: []migration.RunWave{{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "owned-identity", Binding: migration.MemberBinding{
		IssuingAuthorityID: uuid.NewString(), TargetID: "owned-target", TargetRevision: "original", Connector: "nginx", Target: "owned-edge", TargetConfig: json.RawMessage(`{"executor":"agent"}`), RequiredAgentID: agentID,
		TrustAnchorPath: "/owned/anchor.pem", TrustAnchorPEM: []byte("public fixture CA"), TrustAnchorFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		VerifyAddress: "127.0.0.1:443", SubjectCommonName: "owned.example.test", SubjectDNSNames: []string{"owned.example.test"}, PredecessorCertificateID: uuid.NewString(), PredecessorFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordMigrationRun(ctx, h.tenant, orchestrator.MigrationEventID(h.tenant, runID, "start"), run, actions); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RequestServiceNowTicket(ctx, h.tenant, orchestrator.ServiceNowTicketRequest{InstanceURL: "https://owned.example.test", TokenRef: filepath.Join(t.TempDir(), "servicenow-reference"), ShortDescription: "suspended retained ticket"}); err != nil {
		t.Fatal(err)
	}
	// Model restored legacy suspension plus an append-won/queue-lost crash.
	// Only owned fixture rows change; no external target is contacted.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO provider_tenants(tenant_id,slug,name,status,created_at,updated_at) VALUES($1,'recovery-fixture','Recovery fixture','suspended',now(),now())`, h.tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || n != 2 {
		t.Fatalf("suspended tenant prevented startup recovery: healed=%d err=%v", n, err)
	}
	if err := h.store.RequireLiveTenantService(ctx, h.tenant); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("recovery restored service authority: %v", err)
	}
	if n, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || n != 0 {
		t.Fatalf("repeat recovery: healed=%d err=%v", n, err)
	}
	calls := 0
	_, err = h.srv.outbox.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { calls++; return nil }), orchestrator.DestinationScope{IncludePrefixes: []string{orchestrator.DestinationITSMServiceNow}})
	if err != nil || calls != 0 {
		t.Fatalf("recovered suspended work reached receiver: calls=%d err=%v", calls, err)
	}
}
