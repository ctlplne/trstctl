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
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Preparation and signing retain the explicit local fixtures. Actual warm
// projection paths must keep a healthy current key and both tenants intact.
func TestEventProtectionActiveLifetimeWarmRecovery(t *testing.T) {
	for _, mode := range []string{"catch-up", "tail", "served-tail"} {
		t.Run(mode, func(t *testing.T) { eventProtectionActiveWarmRecovery(t, mode) })
	}
}
func eventProtectionActiveWarmRecovery(t *testing.T, mode string) {
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
	head, err = log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	from, err := st.ProjectionCheckpoint(t.Context())
	if err != nil || from >= head {
		t.Fatalf("active fixture has no natural backlog: %d %d %v", from, head, err)
	}
	var before bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { before.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	beforeDigest := crypto.SHA256Hex(before.Bytes())
	projector := projections.New(st, runtime.projectionOptions()...)
	expectedHead := head
	switch mode {
	case "catch-up":
		if err := projector.ProjectCatchUp(t.Context(), log); err != nil {
			t.Fatalf("active catch-up failed: %v", err)
		}
	case "tail", "served-tail":
		worker := projections.NewTailWorker(log, projector, nil, time.Second)
		if mode == "served-tail" {
			worker = srv.tailWorker
		}
		ctx, cancel := context.WithCancel(t.Context())
		runErr := make(chan error, 1)
		done := make(chan struct{})
		stop := func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("active tail did not stop within 5s")
			}
		}
		defer stop()
		const lateID = "0abf0306-e4b7-4bf9-8ce2-49053f1a3427"
		wire, err := json.Marshal(projections.OwnerCreated{ID: lateID, Kind: "team", Name: "Active tail observation", Email: "active-tail@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		appendLate := func() events.Event {
			late, err := log.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: tenant, Data: wire})
			if err != nil || late.Protection == nil {
				t.Fatalf("active out-of-band event was not protected: %v", err)
			}
			return late
		}
		deadline := time.NewTimer(12 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		var late events.Event
		if mode == "tail" {
			// A single attempt returns transient errors to its caller. Feed its idle
			// backlog without a concurrent writer; served-tail exercises the actual
			// bounded service retry loop during concurrent protected publication.
			late = appendLate()
			go func() { defer close(done); runErr <- worker.Run(ctx) }()
		} else {
			go func() { defer close(done); srv.RunProjectionTail(ctx); runErr <- nil }()
			// Finish startup within the SAME end-to-end 12s observation budget,
			// then publish while the served tail is waiting for its next message.
			for worker.Applied() < head {
				select {
				case err := <-runErr:
					t.Fatalf("served active tail stopped during startup: %v", err)
				case <-deadline.C:
					t.Fatal("served active tail did not process initial backlog within 12s")
				case <-ticker.C:
				}
			}
			late = appendLate()
		}
		expectedHead = late.Sequence
		observed := false
		for !observed {
			select {
			case err := <-runErr:
				t.Fatalf("active tail stopped before private owner readback: %v", err)
			case <-deadline.C:
				t.Fatal("active tail did not project private owner within 12s")
			case <-ticker.C:
				got, err := st.GetOwner(t.Context(), tenant, lateID)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) && !store.IsBusy(err) {
					t.Fatal(err)
				}
				observed = err == nil && got.Email == "active-tail@example.invalid" && worker.Applied() >= late.Sequence
			}
		}
		stop()
		if lag, err := worker.Lag(t.Context()); err != nil || lag != 0 {
			t.Fatalf("active tail lag differs: %d %v", lag, err)
		}

	}
	got, err := st.GetOwner(t.Context(), tenant, owner.ID)
	if err != nil || got.Email != owner.Email {
		t.Fatalf("active owner changed: %v", err)
	}
	got, err = st.GetOwner(t.Context(), neighbor, other.ID)
	if err != nil || got.Email != other.Email {
		t.Fatalf("active replay changed neighbor: %v", err)
	}
	actual, found, err := log.EventByID(t.Context(), private.ID)
	if err != nil || !found || actual.SensitiveErased || !bytes.Equal(actual.Data, private.Data) {
		t.Fatalf("active replay erased or changed current private source: %v", err)
	}
	receipt, erased, err := runtime.custody.DestructionReceipt(t.Context(), eventprotect.KeyRef{TenantID: tenant, ID: requested.KeyID})
	if err != nil || erased || receipt != "" {
		t.Fatalf("active key disappeared or acquired removal receipt: %v", err)
	}
	var after bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { after.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	if crypto.SHA256Hex(after.Bytes()) != beforeDigest {
		t.Fatal("active replay rewrote original source prefix")
	}
	checkpoint, err := st.ProjectionCheckpoint(t.Context())
	if err != nil || checkpoint != expectedHead {
		t.Fatalf("active checkpoint differs: %d want %d %v", checkpoint, expectedHead, err)
	}
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopped = true
}
