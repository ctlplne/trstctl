// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Actual configured PG/NATS/preparation/offboard/Drain; request and signing
// retain C189's explicit component fixtures. No full backup/process proof.
func TestEventProtectionErasedLifetimeWarmRecovery(t *testing.T) {
	for _, mode := range []string{"catch-up", "tail"} {
		t.Run(mode, func(t *testing.T) { eventProtectionErasedWarmRecovery(t, mode) })
	}
}
func eventProtectionErasedWarmRecovery(t *testing.T, mode string) {
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
	head, err = log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	from, err := st.ProjectionCheckpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if from >= head {
		t.Fatal("fixture has no naturally lagging private history; do not reset checkpoint to manufacture it")
	}
	var before bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { before.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	beforeDigest := crypto.SHA256Hex(before.Bytes())
	extension := &eventErasureRebuildExtension{}
	options := append(runtime.projectionOptions(), projections.WithEventProjection(extension))
	projector := projections.New(st, options...)
	expectedHead := head
	switch mode {
	case "catch-up":
		if err := projector.ProjectCatchUp(t.Context(), log); err != nil {
			t.Fatalf("warm catch-up failed after completed erasure: %v", err)
		}
		if len(extension.events) == 0 {
			t.Fatal("warm catch-up omitted neighbor extension history")
		}
		for _, event := range extension.events {
			if event.TenantID == tenant {
				t.Fatalf("warm extension received erased lifetime: %s", event.Type)
			}
		}
	case "tail":
		// Do not call catch-up first: the tail must handle its own retained backlog.
		worker := projections.NewTailWorker(log, projector, nil, time.Second)
		ctx, cancel := context.WithCancel(t.Context())
		runErr := make(chan error, 1)
		done := make(chan struct{})
		go func() { defer close(done); runErr <- worker.Run(ctx) }()
		stop := func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("tail did not stop within original tail-test shutdown budget")
			}
		}
		defer stop()
		const lateID = "b1e331aa-4c39-4f76-9c07-a05158dd191e"
		wire, err := json.Marshal(projections.OwnerCreated{ID: lateID, Kind: "team", Name: "Observed from source", Email: "tail-neighbor@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		late, err := log.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: neighbor, Data: wire})
		if err != nil {
			t.Fatal(err)
		}
		expectedHead = late.Sequence
		deadline := time.NewTimer(12 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		observed := false
		for !observed {
			select {
			case err := <-runErr:
				t.Fatalf("tail failed before neighbor readback: %v", err)
			case <-deadline.C:
				t.Fatal("tail did not independently project neighbor within 12s")
			case <-ticker.C:
				got, err := st.GetOwner(t.Context(), neighbor, lateID)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) && !store.IsBusy(err) {
					t.Fatal(err)
				}
				observed = err == nil && got.Email == "tail-neighbor@example.invalid" && worker.Applied() >= late.Sequence
			}
		}
		stop()
		if lag, err := worker.Lag(t.Context()); err != nil || lag != 0 {
			t.Fatalf("tail lag did not settle: %d %v", lag, err)
		}
	}
	eventKeyAssertNoTenantSQLResidue(t, st, tenant)
	got, err := st.GetOwner(t.Context(), neighbor, other.ID)
	if err != nil || got.Email != other.Email {
		t.Fatalf("warm recovery changed neighbor: %v", err)
	}
	actual, found, err := log.EventByID(t.Context(), private.ID)
	if err != nil || !found || !actual.SensitiveErased || len(actual.Data) != 0 {
		t.Fatalf("warm recovery exposed erased private body: %v", err)
	}
	current, found, err := runtime.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !found || current != receipt {
		t.Fatalf("warm recovery changed signed current absence: %v", err)
	}
	var after bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { after.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	if crypto.SHA256Hex(after.Bytes()) != beforeDigest {
		t.Fatal("warm recovery rewrote original source prefix")
	}
	checkpoint, err := st.ProjectionCheckpoint(t.Context())
	if err != nil || checkpoint != expectedHead {
		t.Fatalf("warm recovery skipped source positions or lost checkpoint: %d want %d %v", checkpoint, expectedHead, err)
	}
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopped = true
}
