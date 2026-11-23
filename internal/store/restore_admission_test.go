// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A command and its nested ingress must share one restore session, so the
// key-state and history session locks can be acquired before transaction B.
func TestRestoreIngressSessionBorrowsForNestedAppendCR045(t *testing.T) {
	s := newStore(t)
	const tenant = "49900000-0000-4000-8000-0000000000f2"
	var escaped context.Context
	err := s.WithRestoreIngressSession(t.Context(), func(session context.Context) error {
		escaped = session
		return s.WithGlobalKeyStateAdmission(session, store.KeyStateShared, func(keyState context.Context) error {
			return s.WithRestoreEventIngress(keyState, tenant, "plain-session-event", "tenant.registered",
				func(context.Context) error { return nil })
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := s.WithRestoreIngressSession(escaped, func(context.Context) error {
		called = true
		return nil
	}); !errors.Is(err, store.ErrRestoreAdmissionLost) || called {
		t.Fatalf("expired restore session callback ran: err=%v called=%t", err, called)
	}
}

func TestRestoreMarkerWaitsForActivityAndFencesNewStarts(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	const tenant = "49900000-0000-4000-8000-000000000011"
	const activity = "49900000-0000-4000-8000-000000000012"
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000013",
		ArtifactSHA256: strings.Repeat("a", 64), EventCut: 9, DeploymentID: "restore-target-a",
	}
	entered, release := make(chan struct{}), make(chan struct{})
	activityDone := make(chan error, 1)
	go func() {
		activityDone <- s.WithRestoreActivity(ctx, tenant, activity, "worker", "projection-tail", func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-activityDone:
		t.Fatalf("activity did not start: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	markerDone := make(chan error, 1)
	go func() { markerDone <- s.BeginFullRestore(ctx, marker) }()
	select {
	case err := <-markerDone:
		t.Fatalf("restore marker crossed active worker admission: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	close(release)
	if err := <-activityDone; err != nil {
		t.Fatalf("settle worker activity: %v", err)
	}
	if err := <-markerDone; err != nil {
		t.Fatalf("begin restore after activity settled: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	if err := s.WithRestoreActivity(ctx, tenant, "49900000-0000-4000-8000-000000000014", "worker", "projection-tail", func(context.Context) error {
		t.Fatal("worker callback ran through a committed restore marker")
		return nil
	}); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("new worker after marker=%v, want restore-in-progress", err)
	}
}

func TestRawHistoryOwnerBindsExactEventArtifactDigest(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	marker := store.RestoreMarker{
		OperationID:        "49900000-0000-4000-8000-0000000000f1",
		ArtifactSHA256:     strings.Repeat("a", 64),
		EventHistorySHA256: strings.Repeat("b", 64),
		EventCut:           9,
		DeploymentID:       "restore-target-artifact-bound",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	other := marker
	other.EventHistorySHA256 = strings.Repeat("c", 64)
	if err := s.BeginFullRestore(ctx, other); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("different event artifact reused committed marker: %v", err)
	}
	if err := s.WithFullRestoreOwner(ctx, marker, func(owner context.Context) error {
		if err := s.RequireFullRestoreHistoryOwner(owner, marker.EventCut, marker.EventHistorySHA256); err != nil {
			return err
		}
		if err := s.RequireFullRestoreHistoryOwner(owner, marker.EventCut, other.EventHistorySHA256); !errors.Is(err, store.ErrRestoreInProgress) {
			t.Fatalf("different raw event artifact acquired owner: %v", err)
		}
		if err := s.RequireFullRestoreHistoryOwner(owner, marker.EventCut+1, marker.EventHistorySHA256); !errors.Is(err, store.ErrRestoreInProgress) {
			t.Fatalf("different event cut acquired owner: %v", err)
		}
		called := false
		if err := s.WithRestoreEventIngress(owner, "49900000-0000-4000-8000-000000000011",
			"unrelated-event", "owner.updated", func(context.Context) error {
				called = true
				return nil
			}); !errors.Is(err, store.ErrRestoreInProgress) || called {
			t.Fatalf("full restore owner published unrelated append: err=%v callback=%t", err, called)
		}
		called = false
		if err := s.WithRestoreProjectionAdmission(owner, "49900000-0000-4000-8000-000000000011",
			"unrelated-projection", func(context.Context) error {
				called = true
				return nil
			}); !errors.Is(err, store.ErrRestoreInProgress) || called {
			t.Fatalf("full restore owner projected unrelated event: err=%v callback=%t", err, called)
		}
		tx, err := s.SystemPool().Begin(owner)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := s.RequireRestoreProjectionTx(owner, tx,
			"49900000-0000-4000-8000-000000000011"); !errors.Is(err, store.ErrRestoreInProgress) {
			t.Fatalf("full restore owner bypassed direct projection transaction guard: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNestedRawHistoryOwnerBorrowsCommitLockBehindQueuedWriterCR045(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	marker := store.RestoreMarker{
		OperationID: "49900000-0000-4000-8000-0000000000f2", ArtifactSHA256: strings.Repeat("a", 64),
		EventHistorySHA256: strings.Repeat("b", 64), EventCut: 1, DeploymentID: "plain-nested-raw-owner",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	err := s.WithFullRestoreOwner(ctx, marker, func(owner context.Context) error {
		return s.WithRestoreRawHistoryAdmission(owner, func(outer context.Context) error {
			waiter, err := s.SystemPool().Begin(ctx)
			if err != nil {
				return err
			}
			var pid int
			if err := waiter.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			waitCtx, cancelWait := context.WithCancel(ctx)
			waitDone := make(chan error, 1)
			go func() {
				// The distinct B advisory key is stable by design; this queued
				// exclusive transaction exposes a nested shared-B self-wait.
				_, err := waiter.Exec(waitCtx, `SELECT pg_advisory_xact_lock($1)`, int64(0x6b737461746542))
				waitDone <- err
			}()
			defer func() {
				cancelWait()
				<-waitDone
				_ = waiter.Rollback(context.Background())
			}()
			queued := false
			for attempt := 0; attempt < 100; attempt++ {
				// pg_locks is global PostgreSQL metadata, scoped to this exact
				// disposable waiter backend rather than tenant application rows.
				if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&queued); err != nil {
					return err
				}
				if queued {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !queued {
				return errors.New("exclusive commit-lock writer did not queue")
			}
			inner, stopInner := context.WithTimeout(outer, 300*time.Millisecond)
			defer stopInner()
			return s.WithRestoreRawHistoryAdmission(inner, func(context.Context) error { return nil })
		})
	})
	if err != nil {
		t.Fatalf("nested raw-history admission reacquired B behind its own queued writer: %v", err)
	}
}

func TestDirectIngressCreatesNoActivityBeforeKeyStateCommitLockCR045(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	const tenant = "49900000-0000-4000-8000-0000000000f3"
	const eventID = "plain-direct-ingress-before-key-state"
	holder, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(0x6b737461746542)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
	})
	done := make(chan error, 1)
	go func() {
		done <- s.WithRestoreEventIngress(ctx, tenant, eventID, "tenant.registered",
			func(context.Context) error { return nil })
	}()
	queued := false
	for attempt := 0; attempt < 100; attempt++ {
		if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
			AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
			AND objid::bigint=$1)`, int64(0x61746542)).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		if queued {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !queued {
		t.Fatal("direct ingress did not queue on the held key-state commit lock")
	}
	var starts int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND event_id=$2 AND phase='started'`, tenant, eventID).Scan(&starts); err != nil {
		t.Fatal(err)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if starts != 0 {
		t.Fatalf("direct ingress committed %d activity start(s) before acquiring key-state B", starts)
	}
}

func TestNestedIngressBorrowsExactCommandCommitLockBehindQueuedWriterCR045(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	const tenant = "49900000-0000-4000-8000-0000000000f4"
	const eventID = "plain-nested-command-ingress"
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
	})
	err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		return s.WithTenant(admitted, tenant, func(tx pgx.Tx) error {
			owned, err := s.BindKeyStateOwnerTx(admitted, tx, tenant, store.KeyStateShared)
			if err != nil {
				return err
			}
			waiter, err := s.SystemPool().Begin(ctx)
			if err != nil {
				return err
			}
			var pid int
			if err := waiter.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			waitCtx, cancelWait := context.WithCancel(ctx)
			waitDone := make(chan error, 1)
			go func() {
				_, err := waiter.Exec(waitCtx, `SELECT pg_advisory_xact_lock($1)`, int64(0x6b737461746542))
				waitDone <- err
			}()
			defer func() {
				cancelWait()
				<-waitDone
				_ = waiter.Rollback(context.Background())
			}()
			queued := false
			for attempt := 0; attempt < 100; attempt++ {
				if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&queued); err != nil {
					return err
				}
				if queued {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !queued {
				return errors.New("exclusive command-lock writer did not queue")
			}
			inner, stopInner := context.WithTimeout(owned, 300*time.Millisecond)
			defer stopInner()
			return s.WithRestoreEventIngress(inner, tenant, eventID, "tenant.registered",
				func(context.Context) error { return nil })
		})
	})
	if err != nil {
		t.Fatalf("nested ingress reacquired B behind its own queued writer: %v", err)
	}
}

func TestNestedIngressRejectsOtherTenantOwnerBeforeActivityCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const ownerTenant = "49900000-0000-4000-8000-0000000000f5"
	const otherTenant = "49900000-0000-4000-8000-0000000000f6"
	const eventID = "plain-other-tenant-ingress"
	called := false
	err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		return s.WithTenant(admitted, ownerTenant, func(tx pgx.Tx) error {
			owned, err := s.BindKeyStateOwnerTx(admitted, tx, ownerTenant, store.KeyStateShared)
			if err != nil {
				return err
			}
			return s.WithRestoreEventIngress(owned, otherTenant, eventID, "tenant.registered",
				func(context.Context) error { called = true; return nil })
		})
	})
	if !errors.Is(err, store.ErrKeyStateOwnerUnavailable) || called {
		t.Fatalf("other-tenant command owner reached ingress callback: err=%v called=%t", err, called)
	}
	var starts int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND event_id=$2`, otherTenant, eventID).Scan(&starts); err != nil {
		t.Fatal(err)
	}
	if starts != 0 {
		t.Fatalf("other-tenant command owner created %d ingress activities", starts)
	}
}

func TestSharedCommandOwnerCannotPublishExclusiveKeyStateEventCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000f7"
	const eventID = "plain-exclusive-event-under-shared-owner"
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
	})
	called := false
	err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		return s.WithTenant(admitted, tenant, func(tx pgx.Tx) error {
			owned, err := s.BindKeyStateOwnerTx(admitted, tx, tenant, store.KeyStateShared)
			if err != nil {
				return err
			}
			return s.WithRestoreEventIngress(owned, tenant, eventID, "tenant.offboarded",
				func(context.Context) error { called = true; return nil })
		})
	})
	if !errors.Is(err, store.ErrKeyStateOwnerUnavailable) || called {
		t.Fatalf("shared command published exclusive key-state event: err=%v called=%t", err, called)
	}
}

func TestCommandProjectionTokenSettlesOnlyWithOwnerCommitCR045(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, eventID, wantPhase string
		rollback                         bool
	}{
		{"commit", "49900000-0000-4000-8000-0000000000f8", "plain-command-committed", "terminal", false},
		{"rollback", "49900000-0000-4000-8000-0000000000f9", "plain-command-rolled-back", "started", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			ctx := t.Context()
			t.Cleanup(func() {
				_, _ = s.SystemPool().Exec(context.Background(),
					`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tc.tenant, tc.eventID)
			})
			rollback := errors.New("plain owner rollback")
			err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
				return s.WithTenant(admitted, tc.tenant, func(tx pgx.Tx) error {
					owned, err := s.BindKeyStateOwnerTx(admitted, tx, tc.tenant, store.KeyStateShared)
					if err != nil {
						return err
					}
					if err := s.WithRestoreEventIngress(owned, tc.tenant, tc.eventID, "tenant.registered",
						func(context.Context) error { return nil }); err != nil {
						return err
					}
					pending, err := s.PendingCommandProjectionOperations(owned, tc.tenant, tc.eventID)
					if err != nil || len(pending) != 0 {
						return fmt.Errorf("current owner token appeared as an older replay attempt: ids=%v err=%v", pending, err)
					}
					if err := s.SettleCommandProjectionTx(owned, tx, tc.tenant, tc.eventID); err != nil {
						return err
					}
					var role string
					if err := tx.QueryRow(owned, `SELECT current_role`).Scan(&role); err != nil || role != "trstctl_app" {
						return errors.New("command projection settlement did not restore the application role")
					}
					if tc.rollback {
						return rollback
					}
					return nil
				})
			})
			if tc.rollback && !errors.Is(err, rollback) || !tc.rollback && err != nil {
				t.Fatalf("owner transaction=%v", err)
			}
			var phase string
			if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.restore_activity_tokens
				WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection' AND lane='command-apply'`,
				tc.tenant, tc.eventID).Scan(&phase); err != nil {
				t.Fatal(err)
			}
			if phase != tc.wantPhase {
				t.Fatalf("projection activity phase=%s, want %s", phase, tc.wantPhase)
			}
		})
	}
}

func TestCommandProjectionTokenKeepsAmbiguityAndSettlesProvenNoEffectCR045(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, eventID, wantPhase string
		noEffect                         bool
	}{
		{"no-effect", "49900000-0000-4000-8000-0000000000fa", "plain-command-no-effect", "terminal", true},
		{"ambiguous", "49900000-0000-4000-8000-0000000000fb", "plain-command-ambiguous", "started", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			ctx := t.Context()
			t.Cleanup(func() {
				_, _ = s.SystemPool().Exec(context.Background(),
					`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tc.tenant, tc.eventID)
			})
			cause := errors.New("plain ingress outcome")
			if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
				return s.WithTenant(admitted, tc.tenant, func(tx pgx.Tx) error {
					owned, err := s.BindKeyStateOwnerTx(admitted, tx, tc.tenant, store.KeyStateShared)
					if err != nil {
						return err
					}
					callbackErr := s.WithRestoreEventIngress(owned, tc.tenant, tc.eventID, "tenant.registered",
						func(context.Context) error {
							if tc.noEffect {
								return store.RestoreActivityNoEffect(cause)
							}
							return cause
						})
					if !errors.Is(callbackErr, cause) {
						return errors.New("ingress did not preserve the callback cause")
					}
					return nil
				})
			}); err != nil {
				t.Fatal(err)
			}
			var phase string
			if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.restore_activity_tokens
				WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection' AND lane='command-apply'`,
				tc.tenant, tc.eventID).Scan(&phase); err != nil {
				t.Fatal(err)
			}
			if phase != tc.wantPhase {
				t.Fatalf("projection activity phase=%s, want %s", phase, tc.wantPhase)
			}
		})
	}
}

// CR-045: the current owner may skip canonical refetch only for its own token.
// An older pending attempt with the same event ID still needs retained-source
// comparison before this command can project a read-model row.
func TestCommandProjectionCurrentOwnerDoesNotHideOlderPendingAttemptCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000fd"
	const eventID = "plain-command-duplicate-pending"
	const olderOperation = "49900000-0000-4000-8000-0000000000fe"
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO trstctl_recovery.restore_activity_tokens
		(tenant_id,operation_id,activity_kind,lane,event_id)
		VALUES ($1,$2,'projection','command-apply',$3)`, tenant, olderOperation, eventID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
	})
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		return s.WithTenant(admitted, tenant, func(tx pgx.Tx) error {
			owned, err := s.BindKeyStateOwnerTx(admitted, tx, tenant, store.KeyStateShared)
			if err != nil {
				return err
			}
			if err := s.WithRestoreEventIngress(owned, tenant, eventID, "tenant.registered",
				func(context.Context) error { return nil }); err != nil {
				return err
			}
			olderPending, err := s.NeedsCanonicalCommandProjectionTx(owned, tx, tenant, eventID)
			if err != nil {
				return err
			}
			if !olderPending {
				return errors.New("current owner concealed older pending command projection")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

// CR-045: the producer commitment must be durable under the exact ingress
// activity before its callback can hand bytes to NATS. A journal row created
// after ACK would disappear with the command transaction on rollback.
func TestIngressProducerCommitmentStartsBeforePublishCallbackCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000b1"
	const eventID = "plain-ingress-journal-before-publish"
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
	})
	mac := bytes.Repeat([]byte{0x4a}, 32)
	if err := s.WithRestoreEventIngress(ctx, tenant, eventID, "tenant.registered",
		func(admitted context.Context) error {
			if err := s.StageEventIngressProducer(admitted, store.EventIngressProducerCommitment{
				TenantScope: tenant, EventID: eventID, EventType: "tenant.registered",
				KeyID: "plain-journal-v1", MAC: mac, ExplicitTime: false,
			}); err != nil {
				return err
			}
			var storedMAC []byte
			var phase string
			if err := s.SystemPool().QueryRow(admitted, `SELECT j.producer_mac,j.phase
				FROM trstctl_recovery.event_ingress_journal AS j
				JOIN trstctl_recovery.restore_activity_tokens AS a
				ON a.tenant_id=j.tenant_id AND a.operation_id=j.operation_id
				WHERE j.tenant_id=$1 AND j.event_id=$2 AND a.phase='started'`, tenant, eventID).
				Scan(&storedMAC, &phase); err != nil {
				return err
			}
			if !bytes.Equal(storedMAC, mac) || phase != "started" {
				return errors.New("producer commitment did not precede publication callback")
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
}

// CR-045: the exact serialized wire hash must be committed before broker I/O.
// A new-publish ACK can become verified only with that same hash and sequence;
// a mismatched ACK must leave the candidate pending for recovery.
func TestIngressJournalStagesWireBeforeCanonicalACKCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000b5"
	const eventID = "plain-ingress-wire-before-ack"
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
	})
	wireHash := strings.Repeat("a", 64)
	if err := s.WithRestoreEventIngress(ctx, tenant, eventID, "tenant.registered", func(admitted context.Context) error {
		if err := s.StageEventIngressProducer(admitted, store.EventIngressProducerCommitment{
			TenantScope: tenant, EventID: eventID, EventType: "tenant.registered",
			KeyID: "plain-journal-v1", MAC: bytes.Repeat([]byte{0x4a}, 32),
		}); err != nil {
			return err
		}
		if err := s.StageEventIngressCandidateWire(admitted, wireHash); err != nil {
			return err
		}
		var phase string
		if err := s.SystemPool().QueryRow(admitted, `SELECT phase FROM trstctl_recovery.event_ingress_journal
			WHERE tenant_id=$1 AND event_id=$2 AND attempted_wire_sha256=$3`, tenant, eventID, wireHash).
			Scan(&phase); err != nil || phase != "candidate_staged" {
			return fmt.Errorf("wire commitment before broker callback: phase=%q err=%w", phase, err)
		}
		if err := s.VerifyEventIngressCanonical(admitted, strings.Repeat("b", 64), 7, false); err == nil {
			return errors.New("mismatched new-publish ACK cleared the candidate wire")
		}
		if err := s.VerifyEventIngressCanonical(admitted, wireHash, 7, false); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var phase string
	var seq int64
	if err := s.SystemPool().QueryRow(ctx, `SELECT phase,canonical_sequence
		FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID).
		Scan(&phase, &seq); err != nil || phase != "published_verified" || seq != 7 {
		t.Fatalf("verified new publication phase=%q sequence=%d err=%v", phase, seq, err)
	}
}

// CR-045: a callback that has not prepared broker bytes can prove that it
// published nothing. Once the exact candidate wire is staged, a missing ACK
// is ambiguous and cannot be relabeled as no publication.
func TestIngressJournalNoPublicationRequiresPreWireProofCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000ba"
	for _, tc := range []struct {
		id        string
		stageWire bool
		wantPhase string
	}{
		{"plain-ingress-no-publication", false, "no_publication_verified"},
		{"plain-ingress-ambiguous-publication", true, "candidate_staged"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			t.Cleanup(func() {
				_, _ = s.SystemPool().Exec(context.Background(),
					`DELETE FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2`, tenant, tc.id)
				_, _ = s.SystemPool().Exec(context.Background(),
					`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenant, tc.id)
			})
			err := s.WithRestoreEventIngress(ctx, tenant, tc.id, "tenant.registered", func(admitted context.Context) error {
				if err := s.StageEventIngressProducer(admitted, store.EventIngressProducerCommitment{
					TenantScope: tenant, EventID: tc.id, EventType: "tenant.registered",
					KeyID: "plain-journal-v1", MAC: bytes.Repeat([]byte{0x4a}, 32),
				}); err != nil {
					return err
				}
				if tc.stageWire {
					if err := s.StageEventIngressCandidateWire(admitted, strings.Repeat("a", 64)); err != nil {
						return err
					}
				}
				if err := s.VerifyEventIngressNoPublication(admitted); tc.stageWire {
					if !errors.Is(err, store.ErrRestoreActivityUnresolved) {
						return fmt.Errorf("ambiguous publication accepted as no-effect: %v", err)
					}
					return store.RestoreActivityNoEffect(errors.New("broker outcome still pending"))
				} else if err != nil {
					return err
				}
				return nil
			})
			if tc.stageWire {
				if err == nil || err.Error() != "broker outcome still pending" {
					t.Fatalf("ambiguous callback error=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var phase string
			if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.event_ingress_journal
			WHERE tenant_id=$1 AND event_id=$2`, tenant, tc.id).Scan(&phase); err != nil || phase != tc.wantPhase {
				t.Fatalf("ingress journal phase=%q err=%v, want %q", phase, err, tc.wantPhase)
			}
		})
	}
}

// CR-045 / AN-1: an ordinary tenant can inspect only its own ingress evidence
// and cannot forge a verified broker outcome in the target-local journal.
func TestIngressJournalTenantRLSAndOwnerOnlySettlementCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenantA = "49900000-0000-4000-8000-0000000000b6"
	const tenantB = "49900000-0000-4000-8000-0000000000b7"
	for i, tenant := range []string{tenantA, tenantB} {
		operation := fmt.Sprintf("49900000-0000-4000-8000-0000000000b%d", i+8)
		if _, err := s.SystemPool().Exec(ctx, `INSERT INTO trstctl_recovery.event_ingress_journal
			(tenant_id,operation_id,event_id,event_type,producer_tenant_scope,producer_key_id,producer_mac,explicit_time)
			VALUES ($1,$2,$3,'tenant.registered',$4,'plain-journal-v1',$5,false)`,
			tenant, operation, "plain-rls-"+operation, tenant, bytes.Repeat([]byte{0x4a}, 32)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{tenantA, tenantB} {
			_, _ = s.SystemPool().Exec(context.Background(),
				`DELETE FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1`, tenant)
		}
	})
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var own, neighbor int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.event_ingress_journal
			WHERE tenant_id=$1`, tenantA).Scan(&own); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.event_ingress_journal
			WHERE tenant_id=$1`, tenantB).Scan(&neighbor); err != nil {
			return err
		}
		if own != 1 || neighbor != 0 {
			return fmt.Errorf("ingress journal RLS own=%d neighbor=%d", own, neighbor)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE trstctl_recovery.event_ingress_journal
			SET phase='no_publication_verified',verified_at=now() WHERE tenant_id=$1`, tenantA)
		return err
	}); err == nil {
		t.Fatal("ordinary tenant forged a verified ingress outcome")
	}
}

// CR-045: a legacy or crashed ingress may have a terminal activity token while
// its broker publication is still uncertain. The destination-owned producer
// journal must independently fence full restore until canonical reconciliation.
func TestRestoreMarkerRefusesPendingIngressJournalAfterActivityTerminalCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000b2"
	const operation = "49900000-0000-4000-8000-0000000000b3"
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO trstctl_recovery.event_ingress_journal
		(tenant_id,operation_id,event_id,event_type,producer_tenant_scope,producer_key_id,producer_mac,explicit_time)
		VALUES ($1,$2,'plain-pending-publish','tenant.registered',$4,'plain-journal-v1',$3,false)`,
		tenant, operation, bytes.Repeat([]byte{0x4a}, 32), tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND operation_id=$2`, tenant, operation)
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	marker := store.RestoreMarker{OperationID: "49900000-0000-4000-8000-0000000000b4",
		ArtifactSHA256: strings.Repeat("a", 64), EventCut: 1, DeploymentID: "plain-ingress-fence"}
	if err := s.BeginFullRestore(ctx, marker); !errors.Is(err, store.ErrRestoreActivityUnresolved) {
		t.Fatalf("restore crossed pending keyed ingress journal: %v", err)
	}
}

func TestRestoreMarkerRefusesUnresolvedActivityAfterSessionEnds(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-000000000021"
	const activity = "49900000-0000-4000-8000-000000000022"
	callbackErr := errors.New("effect outcome unknown")
	if err := s.WithRestoreActivity(ctx, tenant, activity, "effect", "secret-sync", func(context.Context) error {
		return callbackErr
	}); !errors.Is(err, callbackErr) {
		t.Fatalf("activity error=%v, want callback error", err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND operation_id=$2`, tenant, activity)
	})
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000023",
		ArtifactSHA256: strings.Repeat("b", 64), EventCut: 10, DeploymentID: "restore-target-b",
	}
	if err := s.BeginFullRestore(ctx, marker); !errors.Is(err, store.ErrRestoreActivityUnresolved) {
		t.Fatalf("marker with unresolved external effect=%v, want refusal", err)
	}
}

func TestRestoreActivitySettlesProvenNoEffect(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-000000000026"
	const operation = "49900000-0000-4000-8000-000000000027"
	cause := errors.New("the operation refused before any effect")
	if err := s.WithRestoreActivity(ctx, tenant, operation, "maintenance", "no-effect-proof",
		func(context.Context) error { return store.RestoreActivityNoEffect(cause) }); !errors.Is(err, cause) {
		t.Fatalf("no-effect cause = %v", err)
	}
	var started bool
	if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND operation_id=$2 AND phase='started')`, tenant, operation).Scan(&started); err != nil || started {
		t.Fatalf("proven no-effect activity remained started: %t, %v", started, err)
	}
}

// CR-045: a failed key transition may already have changed state. Once its
// failure snapshot is durably projected, the attempt is terminal, not no-effect.
func TestRestoreActivitySettlesProvenTerminalFailure(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-000000000028"
	const operation = "49900000-0000-4000-8000-000000000029"
	cause := errors.New("transition failed after durable failure snapshot")
	if err := s.WithRestoreActivity(ctx, tenant, operation, "maintenance", "failed-transition",
		func(context.Context) error { return store.RestoreActivityTerminal(cause) }); !errors.Is(err, cause) {
		t.Fatalf("terminal failure cause = %v", err)
	}
	var phase string
	if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND operation_id=$2`, tenant, operation).Scan(&phase); err != nil || phase != "terminal" {
		t.Fatalf("proven terminal failure phase = %q, %v", phase, err)
	}
}

func TestRestoreMarkerClearanceRequiresExactArtifactAndFinalPhase(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000031",
		ArtifactSHA256: strings.Repeat("c", 64), EventCut: 11, DeploymentID: "restore-target-c",
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishFullRestore(ctx, marker); !errors.Is(err, store.ErrRestoreIncomplete) {
		t.Fatalf("prepared marker cleared before proof: %v", err)
	}
	wrong := marker
	wrong.ArtifactSHA256 = strings.Repeat("d", 64)
	if err := s.AdvanceFullRestore(ctx, wrong, "artifacts_restored"); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("different artifact advanced marker: %v", err)
	}
	for _, phase := range []string{"artifacts_restored", "event_partial", "postgres_imported", "pair_verified", "final_rebuild"} {
		if err := s.AdvanceFullRestore(ctx, marker, phase); err != nil {
			t.Fatalf("advance restore phase %s: %v", phase, err)
		}
	}
	if err := s.FinishFullRestore(ctx, wrong); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("different artifact cleared marker: %v", err)
	}
	if err := s.FinishFullRestore(ctx, marker); err != nil {
		t.Fatalf("clear exact completed marker: %v", err)
	}
	if err := s.WithRestoreActivity(ctx, "49900000-0000-4000-8000-000000000032",
		"49900000-0000-4000-8000-000000000033", "worker", "projection-tail", func(context.Context) error {
			return nil
		}); err != nil {
		t.Fatalf("activity after completed restore remained fenced: %v", err)
	}
}

// CR-045: a broker write whose ACK or readback is still ambiguous must keep
// the target fenced even when every other full-restore phase completed.
func TestFullRestoreMarkerRefusesPendingRawHistoryJournalCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000081",
		ArtifactSHA256: strings.Repeat("c", 64), EventCut: 2,
		DeploymentID: "raw-journal-target",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"artifacts_restored", "event_partial", "postgres_imported", "pair_verified", "final_rebuild"} {
		if err := s.AdvanceFullRestore(ctx, marker, phase); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO trstctl_recovery.raw_history_journal
		(tenant_id,operation_id,artifact_sha256,source_sequence,action,raw_sha256,
		 source_subject,source_message_id)
		VALUES ($1,$2,$3,1,'gap',$4,'events.__trstctl_backup_gap','gap-1')`,
		store.RestoreControlTenantID, marker.OperationID, marker.ArtifactSHA256, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishFullRestore(ctx, marker); !errors.Is(err, store.ErrRestoreIncomplete) {
		t.Fatalf("pending raw broker write cleared marker: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE trstctl_recovery.raw_history_journal
		SET phase='verified',verified_at=now() WHERE tenant_id=$1 AND operation_id=$2`,
		store.RestoreControlTenantID, marker.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishFullRestore(ctx, marker); err != nil {
		t.Fatalf("verified raw broker write still blocked marker: %v", err)
	}
}

// CR-045: raw broker writes and tenant key retirement cannot overlap. The
// session grant must span the entire raw callback, not just its SQL preflight.
func TestRawHistoryRestoreHoldsGlobalKeyStateAdmissionCR045(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- s.WithRestoreRawHistoryAdmission(ctx, func(context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	probe, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	err := s.WithGlobalKeyStateAdmission(probe, store.KeyStateExclusive,
		func(context.Context) error { return nil })
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		<-finished
		t.Fatalf("key-state transition entered during raw broker I/O: %v", err)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive,
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("key-state transition remained blocked after raw restore: %v", err)
	}
}

// CR-045: an uncertain broker outcome remains started across owner sessions;
// only an exact same-artifact resume with verified readback can settle it.
func TestRawHistoryJournalRetainsAmbiguousStartForExactResumeCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	marker := store.RestoreMarker{
		OperationID:        "49900000-0000-4000-8000-000000000091",
		ArtifactSHA256:     strings.Repeat("a", 64),
		EventHistorySHA256: strings.Repeat("b", 64),
		EventCut:           1, DeploymentID: "raw-resume-target",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	record := events.BackupHistoryRecord{Sequence: 1, GapThrough: 1,
		Subject: "events.__trstctl_backup_gap", MessageID: "gap-1"}
	ambiguous := errors.New("broker result unresolved")
	err := s.WithFullRestoreOwner(ctx, marker, func(ownerCtx context.Context) error {
		return s.WithRawHistoryRecordJournal(ownerCtx, 1, marker.EventHistorySHA256,
			"gap", record, func(context.Context) error { return ambiguous })
	})
	if !errors.Is(err, ambiguous) {
		t.Fatalf("ambiguous write result=%v", err)
	}
	var phase string
	if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.raw_history_journal
		WHERE tenant_id=$1 AND operation_id=$2 AND source_sequence=1 AND action='gap'`,
		store.RestoreControlTenantID, marker.OperationID).Scan(&phase); err != nil || phase != "started" {
		t.Fatalf("ambiguous raw journal phase=%q err=%v", phase, err)
	}
	if err := s.WithFullRestoreOwner(ctx, marker, func(ownerCtx context.Context) error {
		return s.WithRawHistoryRecordJournal(ownerCtx, 1, marker.EventHistorySHA256,
			"gap", record, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatalf("same-artifact raw journal resume: %v", err)
	}
	if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.raw_history_journal
		WHERE tenant_id=$1 AND operation_id=$2 AND source_sequence=1 AND action='gap'`,
		store.RestoreControlTenantID, marker.OperationID).Scan(&phase); err != nil || phase != "verified" {
		t.Fatalf("settled raw journal phase=%q err=%v", phase, err)
	}
}

// CR-045: raw restore evidence is target-local, but its tenant partition is
// still visible only to that tenant's runtime role and writable only by the
// audited restore owner.
func TestRawHistoryJournalTenantRLSAndOwnerWriteCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenantA = "49900000-0000-4000-8000-0000000000a1"
	const tenantB = "49900000-0000-4000-8000-0000000000b1"
	const operation = "49900000-0000-4000-8000-0000000000c1"
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO trstctl_recovery.raw_history_journal
		(tenant_id,operation_id,artifact_sha256,source_sequence,action,raw_sha256,source_subject,source_message_id)
		VALUES ($1,$2,$3,1,'live',$4,'events.tenant','message-1')`,
		tenantA, operation, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant string
		want   int
	}{{tenantA, 1}, {tenantB, 0}} {
		if err := s.WithTenant(ctx, tc.tenant, func(tx pgx.Tx) error {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.raw_history_journal
				WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation).Scan(&count); err != nil {
				return err
			}
			if count != tc.want {
				t.Errorf("tenant %s saw %d raw journal rows, want %d", tc.tenant, count, tc.want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE trstctl_recovery.raw_history_journal SET phase='verified', verified_at=now()
			WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation)
		return err
	}); err == nil {
		t.Fatal("ordinary tenant role settled raw history journal")
	}
}

func TestRestoreAdmissionBootstrapsBeforeOrdinaryMigrations(t *testing.T) {
	ctx := t.Context()
	s, err := store.Open(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BootstrapRestoreAdmission(ctx); err != nil {
		t.Fatalf("bootstrap target-local admission without application schema: %v", err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000041",
		ArtifactSHA256: strings.Repeat("e", 64), EventCut: 12, DeploymentID: "restore-target-d",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatalf("commit marker before ordinary migrations: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate marked target: %v", err)
	}
	if err := s.WithRestoreActivity(ctx, "49900000-0000-4000-8000-000000000042",
		"49900000-0000-4000-8000-000000000043", "build", "server", func(context.Context) error {
			t.Fatal("startup ran through the restore marker")
			return nil
		}); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("migrations erased the target marker: %v", err)
	}
}

func TestFullRestoreOwnerRequiresCommittedExactMarker(t *testing.T) {
	s := newStore(t)
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000071",
		ArtifactSHA256: strings.Repeat("f", 64), EventCut: 13, DeploymentID: "restore-target-owner",
	}
	called := false
	callback := func(context.Context) error { called = true; return nil }
	if err := s.WithFullRestoreOwner(t.Context(), marker, callback); !errors.Is(err, store.ErrRestoreInProgress) || called {
		t.Fatalf("owner without marker: err=%v callback=%t", err, called)
	}
	if err := s.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	wrong := marker
	wrong.ArtifactSHA256 = strings.Repeat("a", 64)
	if err := s.WithFullRestoreOwner(t.Context(), wrong, callback); !errors.Is(err, store.ErrRestoreInProgress) || called {
		t.Fatalf("owner for different artifact: err=%v callback=%t", err, called)
	}
	if err := s.WithFullRestoreOwner(t.Context(), marker, callback); err != nil || !called {
		t.Fatalf("owner for exact artifact: err=%v callback=%t", err, called)
	}
	nestedCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	called = false
	if err := s.WithFullRestoreOwner(nestedCtx, marker, func(ownerCtx context.Context) error {
		return s.WithFullRestoreOwner(ownerCtx, marker, callback)
	}); err != nil || !called {
		t.Fatalf("nested exact-artifact owner: err=%v callback=%t", err, called)
	}
}

func TestRestoreAdmissionBootstrapRefusesWeakenedRLS(t *testing.T) {
	s, err := store.Open(t.Context(), createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BootstrapRestoreAdmission(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(t.Context(),
		`ALTER TABLE trstctl_recovery.restore_activity_tokens NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapRestoreAdmission(t.Context()); err == nil {
		t.Fatal("bootstrap accepted a restore activity journal without forced tenant RLS")
	}
}

// CR-045: a partially upgraded target may retain markers and activity rows
// while losing the producer/wire journal. Bootstrap must fail closed before
// serving or mutating that target.
func TestRestoreAdmissionBootstrapRefusesMissingIngressJournalCR045(t *testing.T) {
	s, err := store.Open(t.Context(), createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BootstrapRestoreAdmission(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(t.Context(), `DROP TABLE trstctl_recovery.event_ingress_journal`); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapRestoreAdmission(t.Context()); err == nil {
		t.Fatal("bootstrap accepted a restore admission schema without its ingress journal")
	}
}

func TestRawRebuildReadModelTxRefusesRestoreMarker(t *testing.T) {
	s := newStore(t)
	const tenant = "49900000-0000-4000-8000-000000000121"
	if err := s.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant, Name: "raw rebuild guard"}); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000122",
		ArtifactSHA256: strings.Repeat("b", 64), EventCut: 0, DeploymentID: "raw-rebuild-target",
	}
	if err := s.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	if err := s.RebuildReadModelTx(t.Context(), func(pgx.Tx) error { return nil }); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("raw store rebuild under marker=%v, want restore refusal", err)
	}
	if _, err := s.GetTenant(t.Context(), tenant); err != nil {
		t.Fatalf("raw store rebuild changed tenant before refusal: %v", err)
	}
}

func TestRawRestoreReadModelTxRefusesRestoreMarker(t *testing.T) {
	s := newStore(t)
	const tenant = "49900000-0000-4000-8000-000000000124"
	if err := s.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant, Name: "raw snapshot guard"}); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000125",
		ArtifactSHA256: strings.Repeat("c", 64), EventCut: 0, DeploymentID: "raw-snapshot-target",
	}
	if err := s.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	if err := s.RestoreReadModelTx(t.Context(), func(pgx.Tx) error { return nil }); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("raw store snapshot restore under marker=%v, want restore refusal", err)
	}
	if _, err := s.GetTenant(t.Context(), tenant); err != nil {
		t.Fatalf("raw store snapshot restore changed tenant before refusal: %v", err)
	}
}

func TestRestoreMarkerRefusesNonSecretRemoteReceiverWithNoLiveSession(t *testing.T) {
	s := newStore(t)
	const tenant = "49900000-0000-4000-8000-000000000131"
	if err := s.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant, Name: "late receiver"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO outbox
			(tenant_id,destination,effect_lane,payload,idempotency_key,status,attempts,receiver_pending_ids)
			VALUES ($1,'webhook.fixture','webhook.fixture',$2,'restore-late-receiver','delivered',1,
			ARRAY['49900000-0000-4000-8000-000000000132'::uuid])`, tenant, []byte(`{}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000133",
		ArtifactSHA256: strings.Repeat("c", 64), EventCut: 1, DeploymentID: "receiver-target",
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	if err := s.BeginFullRestore(t.Context(), marker); !errors.Is(err, store.ErrRestoreActivityUnresolved) {
		t.Fatalf("full restore with unproven remote receiver=%v, want refusal", err)
	}
}

func TestCleanServerDrainSettlesLifetimeTokenAfterRunCancellation(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	const tenant = "49900000-0000-4000-8000-000000000151"
	const activity = "49900000-0000-4000-8000-000000000152"
	if err := s.WithRestoreActivityAfterDrain(ctx, tenant, activity, "build", "server-lifetime",
		func(context.Context) error {
			cancel() // the server has joined all workers and drained its listener
			return nil
		}); err != nil {
		t.Fatalf("settle fully drained server after cancellation: %v", err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000153",
		ArtifactSHA256: strings.Repeat("e", 64), EventCut: 0, DeploymentID: "drained-server-target",
	}
	if err := s.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatalf("drained server still blocks restore: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
}
