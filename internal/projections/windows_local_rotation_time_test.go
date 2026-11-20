// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CR-156: an old prepared event can hold sub-microsecond precision even
// though PostgreSQL stores the projected timestamp at microsecond precision.
func TestWindowsLocalPreparedNanosecondsDoNotStopRetainedRotation(t *testing.T) {
	t.Run("tail restart after exhausted dispatch", func(t *testing.T) {
		s, log, queued, intent, epoch := windowsPreparedTimeFixture(t)
		runWindowsPreparedTailThrough(t, s, log, queued.Sequence)
		ctx := t.Context()
		cmd, err := s.GetSecretStaticRotationCommand(ctx, tenantA, intent.RotationID)
		if err != nil || cmd.Phase != store.SecretStaticRotationQueued {
			t.Fatalf("initial rotation phase = %s, %v", cmd.Phase, err)
		}
		// Model the exact owned delivery row after its retry budget was
		// exhausted. Catch-up must create the native job without silently
		// erasing that job's failure record.
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET status='failed', last_error='external_delivery_failed'
				WHERE tenant_id=$1 AND id=$2`, tenantA, cmd.OutboxID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		prepared := appendWindowsPreparedNanosecondEvent(t, log, queued, intent, epoch)
		later := appendJSONEvent(t, log, projections.EventOwnerCreated, tenantA,
			projections.OwnerCreated{ID: uuid.NewString(), Kind: "Service", Name: "after-retained-preparation"})
		runWindowsPreparedTailThrough(t, s, log, later.Sequence)
		cmd, err = s.GetSecretStaticRotationCommand(ctx, tenantA, intent.RotationID)
		if err != nil || cmd.Phase != store.SecretStaticRotationPrepared {
			t.Fatalf("replayed rotation phase = %s, %v", cmd.Phase, err)
		}
		native, err := s.GetWindowsLocalRotation(ctx, tenantA, intent.RotationID)
		if err != nil || native.PreparedEventID != prepared.ID || !native.PreparedAt.Equal(prepared.Time.Truncate(time.Microsecond)) ||
			native.OutboxID == nil {
			t.Fatalf("tail did not project the exact preparation and host job: %v", err)
		}
		job, err := s.GetOutboxAttemptByKey(ctx, tenantA, hostaccounts.RotationDestination, store.WindowsLocalRotationOutboxKey(epoch, intent.RotationID))
		if err != nil || job.ID != *native.OutboxID || job.Status != "pending" {
			t.Fatalf("retained preparation did not queue its host job: %+v, %v", job, err)
		}
		old, err := s.GetOutboxAttemptByKey(ctx, tenantA, store.SecretStaticRotationDestination, store.SecretStaticRotationOutboxIdempotencyKey(epoch, intent.RotationID))
		if err != nil || old.Status != "failed" || old.LastError != "external_delivery_failed" {
			t.Fatalf("original exhausted delivery lost its diagnostic: %+v, %v", old, err)
		}
	})
	t.Run("canonical reader compares the persisted instant", func(t *testing.T) {
		s, log, queued, intent, epoch := windowsPreparedTimeFixture(t)
		runWindowsPreparedTailThrough(t, s, log, queued.Sequence)
		prepared := appendWindowsPreparedNanosecondEvent(t, log, queued, intent, epoch)
		// Seed an already-projected row independently of the tail's input
		// precision so this test catches the canonical-reader comparison.
		projection := prepared
		projection.Time = projection.Time.Truncate(time.Microsecond)
		if err := projections.New(s).Apply(t.Context(), projection); err != nil {
			t.Fatal(err)
		}
		native, command, err := projections.CanonicalWindowsLocalRotation(t.Context(), s, log, tenantA, intent.RotationID)
		if err != nil || native.Intent != intent || command.Phase != store.SecretStaticRotationPrepared {
			t.Fatalf("native claim and redemption lost their retained authority: %v", err)
		}
		if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `UPDATE windows_local_account_rotations SET prepared_at = $3
				WHERE tenant_id=$1 AND id=$2`, tenantA, intent.RotationID, projection.Time.Add(time.Microsecond))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := projections.CanonicalWindowsLocalRotation(t.Context(), s, log, tenantA, intent.RotationID); err == nil {
			t.Fatal("a different stored microsecond became canonical")
		}
	})
}

func windowsPreparedTimeFixture(t *testing.T) (*store.Store, *events.Log, events.Event, hostaccounts.RotationIntent, string) {
	t.Helper()
	s, log := newStore(t), openLog(t)
	registration := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "time-review"})
	if err := projections.New(s).Apply(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	epoch, err := s.ApplicationSecretTenantEpoch(t.Context(), tenantA)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := hostaccounts.NewRotationIntent(hostaccounts.RotationIntent{
		RotationID: uuid.NewString(), AccountID: uuid.NewString(), TenantID: tenantA, AgentID: uuid.NewString(), InventoryRunID: uuid.NewString(),
		Native: winaccounts.RotationBinding{
			Machine: winaccounts.Machine{Name: "OWNED-HOST", SID: "S-1-5-21-1-2-3", Role: 3},
			Account: winaccounts.Account{Name: "Owned Admin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := strings.Repeat("a", 64)
	payload := projections.SecretStaticRotationQueued{ID: intent.RotationID, TenantEpoch: epoch,
		Provider: "host-sam", ProviderBinding: binding, Key: "hosts/admin", OldRef: "none", ExpectedVersion: 1,
		IdempotencyKeyDigest: crypto.SHA256Hex([]byte(intent.RotationID)), RequestBinding: binding, SinglePhaseAcknowledged: true}
	queued := appendWindowsPreparedTimeEvent(t, log, intent.RotationID, projections.EventSecretStaticRotationQueued,
		registration.Time, 1, payload)
	return s, log, queued, intent, epoch
}

func appendWindowsPreparedNanosecondEvent(t *testing.T, log *events.Log, queued events.Event, intent hostaccounts.RotationIntent, epoch string) events.Event {
	t.Helper()
	return appendWindowsPreparedTimeEvent(t, log, uuid.NewString(), projections.EventSecretStaticRotationAdvanced,
		queued.Time.Truncate(time.Microsecond).Add(time.Millisecond+789*time.Nanosecond), 2, projections.SecretStaticRotationAdvanced{
			ID: intent.RotationID, TenantEpoch: epoch, FromPhase: store.SecretStaticRotationQueued, Phase: store.SecretStaticRotationPrepared,
			ProviderType: "windows", SealedPreparation: []byte("sealed preparation fixture"), SealedOld: []byte("sealed predecessor fixture"),
			WindowsLocalIntent: &intent,
		})
}

func appendWindowsPreparedTimeEvent(t *testing.T, log *events.Log, id, kind string, at time.Time, version int, payload any) events.Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(t.Context(), events.Event{ID: id, TenantID: tenantA, Type: kind, SchemaVersion: version, Time: at, Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func runWindowsPreparedTailThrough(t *testing.T, s *store.Store, log *events.Log, through uint64) {
	t.Helper()
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	tail := projections.NewTailWorker(log, projections.New(s), nil, time.Second)
	done := make(chan error, 1)
	go func() { done <- tail.Run(ctx) }()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for tail.Applied() < through {
		select {
		case err := <-done:
			t.Fatalf("restarted tail stopped at sequence %d before %d: %v", tail.Applied(), through, err)
		case <-ctx.Done():
			t.Fatalf("restarted tail stalled at sequence %d before %d", tail.Applied(), through)
		case <-tick.C:
		}
	}
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("projection tail did not stop")
	}
}
