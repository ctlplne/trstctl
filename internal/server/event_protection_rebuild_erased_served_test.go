// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Public request remains a source fixture; signing is an RPC fixture in this
// test process. RunRebuild itself is the actual operator entry point.
func TestEventProtectionCompletedWorkerErasureSurvivesOperatorRebuild(t *testing.T) {
	for _, mode := range []string{"completed-source", "older-source-cut", "later-registration"} {
		t.Run(mode, func(t *testing.T) { eventProtectionCompletedRebuild(t, mode) })
	}
}
func eventProtectionCompletedRebuild(t *testing.T, mode string) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = serverTestPostgresDSN(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas = 1
	cfg.NATS.AllowSingleReplica = true
	configureExternalAuditTestSigner(t, cfg)
	signer, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "c6c9f597-d2cb-4754-bd52-682e4be0cce2"
	const neighbor = "d074fd2a-38ba-4924-865a-eb58de2b1177"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"Erased rebuild fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: neighbor, Data: []byte(`{"name":"Rebuild neighbor"}`)}); err != nil {
		t.Fatal(err)
	}
	requested, err := eventprivacy.NewRequested(tenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(requested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(requested), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, runtime.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = srv.Shutdown(t.Context())
		}
	}()
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	owner, err := srv.orch.CreateOwner(t.Context(), tenant, "team", "Erased owner", "erased-rebuild@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other, err := srv.orch.CreateOwner(t.Context(), neighbor, "team", "Neighbor owner", "rebuild-neighbor@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var private events.Event
	if err := log.ReplayTenantTypesThrough(t.Context(), tenant, 1, head, []string{projections.EventOwnerCreated}, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(owner.ID)) {
			private = event
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if private.ID == "" || private.Protection == nil {
		t.Fatal("fixture did not protect actual owner event")
	}
	// A retained historical same-lifetime name refresh is a source fixture.
	// Current registration commands deliberately refuse changing a live identity.
	if _, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"Historical name refresh"}`)}); err != nil {
		t.Fatal(err)
	}
	// Typed private lifecycle source fixtures exercise both preflight decoders;
	// no external credential issuance or secret delivery is claimed here.
	pendingWire, err := json.Marshal(projections.DynamicSecretLeasePending{ID: "erased-rebuild-lease", Provider: "postgres", Role: "reader", IdempotencyKey: "erased-rebuild-lease-command", ExpiresAt: time.Now().UTC().Add(time.Minute), HardExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	syncWire, err := json.Marshal(projections.SecretSyncQueued{ID: "erased-rebuild-sync", SecretName: "erased/database", SecretVersion: 1, Target: "ci", RemoteKey: "TOKEN", ValueDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IdempotencyKey: "erased-rebuild-sync-command", Sealed: []byte("sealed fixture")})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []events.Event{{Type: projections.EventDynamicSecretLeasePending, Data: pendingWire}, {Type: projections.EventSecretSyncQueued, Data: syncWire}} {
		event.TenantID = tenant
		if stored, err := log.Append(t.Context(), event); err != nil || stored.Protection == nil {
			t.Fatalf("private preflight source fixture not protected: %v", err)
		}
	}
	var oldCut []events.BackupHistoryRecord
	oldHead, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var oldRaw bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), oldHead, func(record events.BackupHistoryRecord) error {
		record.Stored = bytes.Clone(record.Stored)
		oldCut = append(oldCut, record)
		oldRaw.Write(record.Stored)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventKeyAssertNoTenantSQLResidue(t, st, tenant)
	ref := eventprotect.KeyRef{TenantID: tenant, ID: requested.KeyID}
	receipt, erased, err := runtime.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !erased {
		t.Fatalf("no actual signed destruction: %v", err)
	}
	var currentOwner store.Owner
	var currentStart uint64
	if mode == "later-registration" {
		if err := srv.orch.RegisterTenant(t.Context(), tenant, "New registration after erasure", "erased-rebuild-new-lifetime"); err != nil {
			t.Fatal(err)
		}
		currentLife, err := runtime.policy.LatestLifetime(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		currentStart = currentLife.Registration.Sequence
		currentOwner, err = srv.orch.CreateOwner(t.Context(), tenant, "team", "Current owner", "current-rebuild@example.invalid")
		if err != nil {
			t.Fatal(err)
		}
	}
	head, err = log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var before bytes.Buffer
	expectedRecords := 0
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error {
		before.Write(record.Stored)
		expectedRecords++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	beforeDigest := crypto.SHA256Hex(before.Bytes())
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopped = true
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if mode == "older-source-cut" {
		cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
		transferStore, err := store.Open(t.Context(), cfg.Postgres.DSN)
		if err != nil {
			t.Fatal(err)
		}
		older, protection, err := openConfiguredEventSource(t.Context(), cfg, transferStore, key, false, nil)
		if err != nil {
			transferStore.Close()
			t.Fatal(err)
		}
		_, restoreErr := older.RestoreBackupHistory(t.Context(), oldHead, crypto.SHA256Hex(oldRaw.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
			for _, record := range oldCut {
				if err := yield(record); err != nil {
					return err
				}
			}
			return nil
		})
		closeErr := errors.Join(older.Close(), protection.Close())
		transferStore.Close()
		if err := errors.Join(restoreErr, closeErr); err != nil {
			t.Fatal(err)
		}
		head = oldHead
		expectedRecords = len(oldCut)
		beforeDigest = crypto.SHA256Hex(oldRaw.Bytes())
	}
	extension := &eventErasureRebuildExtension{}
	n, rebuildErr := RunRebuild(t.Context(), cfg, func(context.Context, *config.Config, *license.Manager, *store.Store, *events.Log) ([]projections.Option, error) {
		return []projections.Option{projections.WithEventProjection(extension)}, nil
	})
	if rebuildErr != nil || n != expectedRecords {
		t.Errorf("operator rebuild did not reconcile completed erasure: n=%d head=%d err=%v", n, head, rebuildErr)
	}
	afterStore, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(afterStore.Close)
	if mode != "later-registration" {
		eventKeyAssertNoTenantSQLResidue(t, afterStore, tenant)
	} else {
		if _, err := afterStore.GetOwner(t.Context(), tenant, owner.ID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("retired owner reappeared: %v", err)
		}
		got, err := afterStore.GetOwner(t.Context(), tenant, currentOwner.ID)
		if err != nil || got.Email != currentOwner.Email {
			t.Fatalf("later registration was erased: %v", err)
		}
	}
	if len(extension.events) == 0 {
		t.Fatal("extension did not receive neighbor history")
	}
	for _, event := range extension.events {
		if event.TenantID == tenant && (mode != "later-registration" || event.Sequence < currentStart) {
			t.Fatalf("erased source reached extension: %s", event.Type)
		}
	}
	got, err := afterStore.GetOwner(t.Context(), neighbor, other.ID)
	if err != nil || got.Email != other.Email {
		t.Fatalf("operator rebuild lost or changed neighbor: %v", err)
	}
	again, after, err := openConfiguredEventSource(t.Context(), cfg, afterStore, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = after.Close() })
	t.Cleanup(func() { _ = again.Close() })
	actual, found, err := again.EventByID(t.Context(), private.ID)
	if err != nil || !found || !actual.SensitiveErased || len(actual.Data) != 0 {
		t.Fatalf("operator rebuild made protected private source readable: %v", err)
	}
	gotReceipt, found, err := after.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !found || gotReceipt != receipt {
		t.Fatalf("rebuild changed current destruction evidence: %v", err)
	}
	var rawAfter bytes.Buffer
	if err := again.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { rawAfter.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	if crypto.SHA256Hex(rawAfter.Bytes()) != beforeDigest {
		t.Fatal("rebuild rewrote retained source bytes")
	}
	if rebuildErr == nil {
		var applied uint64
		if err := afterStore.SystemPool().QueryRow(t.Context(), `SELECT applied_seq FROM projection_checkpoint WHERE id=1`).Scan(&applied); err != nil || applied != head {
			t.Fatalf("rebuild checkpoint differs from processed source: %d %v", applied, err)
		}
	}
}

// In-memory observer of the recovery seam only; no transactional persistence or
// rollback claim. It records the exact events delivered to an optional extension.
type eventErasureRebuildExtension struct{ events []events.Event }

func (*eventErasureRebuildExtension) Name() string                  { return "erasure-rebuild-observer" }
func (e *eventErasureRebuildExtension) Reset(context.Context) error { e.events = nil; return nil }
func (e *eventErasureRebuildExtension) Apply(_ context.Context, event events.Event) error {
	e.events = append(e.events, event)
	return nil
}
func (e *eventErasureRebuildExtension) ResetTx(ctx context.Context, _ pgx.Tx) error {
	return e.Reset(ctx)
}
func (e *eventErasureRebuildExtension) ApplyTx(ctx context.Context, _ pgx.Tx, event events.Event) error {
	return e.Apply(ctx, event)
}
func (*eventErasureRebuildExtension) ProjectsTenantLifecycle() {}
func (e *eventErasureRebuildExtension) ReplayTenantLifecycleTx(ctx context.Context, _ pgx.Tx, event events.Event) error {
	return e.Apply(ctx, event)
}
