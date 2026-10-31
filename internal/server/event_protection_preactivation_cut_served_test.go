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
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Explicit request/RPC fixtures, actual worker offboard and RunRebuild. The old
// plaintext remains readable; the current authority must stop resurrection/new
// plaintext in a retired registration, without inventing activation or offboard.
func TestEventProtectionCurrentCustodyFencesSourceCutBeforeActivation(t *testing.T) {
	for _, mode := range []string{"rebuild", "catch-up", "tail"} {
		t.Run(mode, func(t *testing.T) { eventProtectionPreactivationCut(t, mode) })
	}
}
func eventProtectionPreactivationCut(t *testing.T, mode string) {
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
	const tenant = "223b892b-1ef7-4315-b78f-210f6a0f2b5d"
	const neighbor = "e2cd274c-e9dc-42e6-b3e8-0bbef01148b4"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"Before activation"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: neighbor, Data: []byte(`{"name":"Unchanged neighbor"}`)}); err != nil {
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
	legacy, err := srv.orch.CreateOwner(t.Context(), tenant, "team", "Legacy fixture", "legacy-cut@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other, err := srv.orch.CreateOwner(t.Context(), neighbor, "team", "Neighbor fixture", "preactivation-neighbor@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	oldHead, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var history []events.BackupHistoryRecord
	var raw bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), oldHead, func(record events.BackupHistoryRecord) error {
		record.Stored = bytes.Clone(record.Stored)
		history = append(history, record)
		raw.Write(record.Stored)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var legacyReadable bool
	if err := log.ReplayTenantTypesThrough(t.Context(), tenant, 1, oldHead, []string{projections.EventOwnerCreated}, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(legacy.ID)) {
			legacyReadable = event.Protection == nil && !event.SensitiveErased && bytes.Contains(event.Data, []byte(legacy.Email))
		}
		return nil
	}); err != nil || !legacyReadable {
		t.Fatalf("fixture did not capture readable unprotected pre-feature data: %v", err)
	}
	request, err := eventprivacy.NewRequested(tenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, runtime.projectionOptions()...).Apply(t.Context(), requested); err != nil {
		t.Fatal(err)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.CreateOwner(t.Context(), tenant, "team", "Protected fixture", "protected-cut@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventKeyAssertNoTenantSQLResidue(t, st, tenant)
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopped = true
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	transferStore, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	older, oldRuntime, err := openConfiguredEventSource(t.Context(), cfg, transferStore, key, false, nil)
	if err != nil {
		transferStore.Close()
		t.Fatal(err)
	}
	_, restoreErr := older.RestoreBackupHistory(t.Context(), oldHead, crypto.SHA256Hex(raw.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
		for _, record := range history {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	})
	closeErr := older.Close()
	runtimeErr := oldRuntime.Close()
	transferStore.Close()
	if restoreErr != nil || closeErr != nil || runtimeErr != nil {
		t.Fatalf("exact source transfer failed: %v %v %v", restoreErr, closeErr, runtimeErr)
	}

	afterStore, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(afterStore.Close)
	again, after, err := openConfiguredEventSource(t.Context(), cfg, afterStore, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = after.Close() })
	t.Cleanup(func() { _ = again.Close() })
	// Grow the restored branch beyond the original activation's numeric
	// position using independent tenant events. Sequence alone is no floor.
	lateIDs := []string{"ca5cb5e5-e2ac-42a7-b7dc-0303951ca601", "ca5cb5e5-e2ac-42a7-b7dc-0303951ca602", "ca5cb5e5-e2ac-42a7-b7dc-0303951ca603"}
	var newHead uint64
	for _, id := range lateIDs {
		wire, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: "team", Name: "Neighbor branch", Email: "branch-neighbor@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		event, err := again.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: neighbor, Data: wire})
		if err != nil {
			t.Fatal(err)
		}
		newHead = event.Sequence
	}
	from, err := afterStore.ProjectionCheckpoint(t.Context())
	if err != nil || from >= oldHead {
		t.Fatalf("fixture has no natural old-cut backlog: %d %d %v", from, oldHead, err)
	}
	switch mode {
	case "rebuild":
		n, err := RunRebuild(t.Context(), cfg)
		if err != nil || n != len(history)+len(lateIDs) {
			t.Fatalf("old cut rebuild failed: %d %v", n, err)
		}
	case "catch-up":
		if err := projections.New(afterStore, after.projectionOptions()...).ProjectCatchUp(t.Context(), again); err != nil {
			t.Fatal(err)
		}
	case "tail":
		worker := projections.NewTailWorker(again, projections.New(afterStore, after.projectionOptions()...), nil, time.Second)
		ctx, cancel := context.WithCancel(t.Context())
		runErr := make(chan error, 1)
		done := make(chan struct{})
		go func() { defer close(done); runErr <- worker.Run(ctx) }()
		stop := func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("old-cut tail did not stop within 5s")
			}
		}
		defer stop()
		deadline := time.NewTimer(12 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		observed := false
		for !observed {
			select {
			case err := <-runErr:
				t.Fatalf("old-cut tail stopped: %v", err)
			case <-deadline.C:
				t.Fatal("old-cut tail did not independently project neighbor within 12s")
			case <-ticker.C:
				got, err := afterStore.GetOwner(t.Context(), neighbor, lateIDs[len(lateIDs)-1])
				if err != nil && !errors.Is(err, pgx.ErrNoRows) && !store.IsBusy(err) {
					t.Fatal(err)
				}
				observed = err == nil && got.Email == "branch-neighbor@example.invalid" && worker.Applied() >= newHead
			}
		}
		stop()
	}
	for _, id := range lateIDs {
		if got, err := afterStore.GetOwner(t.Context(), neighbor, id); err != nil || got.Email != "branch-neighbor@example.invalid" {
			t.Fatalf("independent restored branch failed: %v", err)
		}
	}
	if checkpoint, err := afterStore.ProjectionCheckpoint(t.Context()); err != nil || checkpoint != newHead {
		t.Fatalf("old-cut replay lost source positions: %d %d %v", checkpoint, newHead, err)
	}
	var rawAfter bytes.Buffer
	if err := again.ExportBackupHistoryThrough(t.Context(), oldHead, func(record events.BackupHistoryRecord) error { rawAfter.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.Bytes(), rawAfter.Bytes()) {
		t.Fatal("old-cut floor rewrote retained plaintext source prefix")
	}
	// Do not claim pre-feature plaintext became cryptographically unreadable.
	var foundLegacy bool
	if err := again.ReplayTenantTypesThrough(t.Context(), tenant, 1, oldHead, []string{projections.EventOwnerCreated}, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(legacy.ID)) {
			foundLegacy = !event.SensitiveErased && event.Protection == nil && bytes.Contains(event.Data, []byte(legacy.Email))
		}
		return nil
	}); err != nil || !foundLegacy {
		t.Fatalf("old plaintext limit changed or hidden: %v", err)
	}
	got, err := afterStore.GetOwner(t.Context(), neighbor, other.ID)
	if err != nil || got.Email != other.Email {
		t.Fatalf("old-cut floor changed neighbor: %v", err)
	}
	beforeHead, err := again.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: tenant, Data: []byte(`{"id":"c2d7358b-5fa9-4118-8984-12d98fbc6f14","kind":"team","name":"Must refuse","email":"must-refuse@example.invalid"}`)}); err == nil {
		t.Error("current erased registration accepted new private plaintext from old source cut")
	}
	afterHead, err := again.LastSequence(t.Context())
	if err != nil || afterHead != beforeHead {
		t.Errorf("refused mutation changed old source head: %d %d %v", beforeHead, afterHead, err)
	}
	for _, candidate := range []events.Event{
		{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"Must not refresh retired registration"}`)},
		{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire},
	} {
		if _, err := again.Append(t.Context(), candidate); err == nil {
			t.Errorf("old-cut floor admitted retired control %s", candidate.Type)
		}
	}
	if finalHead, err := again.LastSequence(t.Context()); err != nil || finalHead != beforeHead {
		t.Errorf("refused retired controls extended source: %d %d %v", finalHead, beforeHead, err)
	}
	eventKeyAssertNoTenantSQLResidue(t, afterStore, tenant)
}
