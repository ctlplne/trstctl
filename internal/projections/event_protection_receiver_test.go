// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This real PostgreSQL/NATS/file-custody receiver test does not qualify the
// production startup, HTTP/CLI/console or post-offboard destruction worker.
func TestEventProtectionReceiverActivatesFromCommittedIntent(t *testing.T) {
	runPreparationReceiverFixture(t, false)
}

func TestEventProtectionReceiverRecoversAfterCreationBeforeActivation(t *testing.T) {
	runPreparationReceiverFixture(t, true)
}

func TestEventProtectionActivationMissingCustodyRetainsPendingInvocations(t *testing.T) {
	runPreparationReceiverFixtureMode(t, false, true, false)
}

func TestEventProtectionActiveRetryNeverProvisionsMissingHistoricalCustody(t *testing.T) {
	runPreparationReceiverFixtureMode(t, false, false, true)
}

func runPreparationReceiverFixture(t *testing.T, interrupt bool) {
	runPreparationReceiverFixtureMode(t, interrupt, false, false)
}

func runPreparationReceiverFixtureMode(t *testing.T, interrupt, missingCustody, lateMissingCustody bool) {
	s := newStore(t)
	base := t.TempDir()
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{
		Directory: filepath.Join(base, "independent-keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: s,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	admission := &eventprivacy.SourceAdmission{Guard: s, Custody: keys}
	reader := &eventprivacy.SourceKeys{Custody: keys}
	receiver := &eventprivacy.PreparationReceiver{Claims: s, Guard: s, Custody: keys}
	verifier := &eventprivacy.ActivationVerifier{Custody: keys}
	p := projections.New(s, projections.WithEventProtectionActivationVerifier(verifier))
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")},
		func(log *events.Log) {
			admission.Policy.Log = log
			reader.Policy.Log = log
			receiver.Policy.Log = log
			verifier.Policy.Log = log
		},
		events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)), events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	record := func(ctx context.Context, next events.Event) (events.Event, error) {
		var result events.Event
		err := s.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
			var err error
			result, err = log.Append(ctx, next)
			if err != nil {
				return err
			}
			return p.ApplyTx(ctx, tx, result)
		})
		return result, err
	}
	interrupted := false
	receiver.Record = func(ctx context.Context, next events.Event) (events.Event, error) {
		if interrupt && !interrupted {
			interrupted = true
			return events.Event{}, errors.New("fixture interruption after key creation, before source submission")
		}
		return record(events.ContextWithoutActor(ctx), next)
	}
	actorCtx := events.ContextWithActor(t.Context(), events.Actor{Subject: "fixture-operator@example.invalid"})
	registered, err := record(actorCtx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("fixture")})
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenantA, registered.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := record(actorCtx, events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenantA, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	if requested.Actor == nil {
		t.Fatal("request lost authenticated attribution")
	}
	if missingCustody {
		missing, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "missing-custody"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: s})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = missing.Close() })
		verifier.Custody = missing
	}
	box := orchestrator.NewOutbox(s, orchestrator.WithTenantServiceCheck(s.RequireLiveTenantService), orchestrator.WithBackoff(func(int) time.Duration { return 0 }))
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		if message.Destination != store.EventKeyPreparationDestination {
			t.Fatal("unrelated destination reached preparation")
		}
		var command store.EventKeyPreparationCommand
		if err := json.Unmarshal(message.Payload, &command); err != nil {
			return err
		}
		return receiver.Prepare(ctx, store.EventKeyPreparationClaim{ID: message.ID, AttemptID: message.ReceiverAttemptID, Attempts: message.Attempts, Command: command})
	})
	worked, err := box.DispatchOneScoped(actorCtx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}})
	if err != nil || !worked {
		t.Fatalf("dispatch committed preparation: worked=%v err=%v", worked, err)
	}
	if missingCustody {
		if err := s.RequireTenantAgentWorkQuiescent(t.Context(), tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Fatalf("missing independent custody cleared pending invocations: %v", err)
		}
		verifier.Custody = keys
		if worked, err := box.DispatchOneScoped(actorCtx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || !worked {
			t.Fatalf("recover after restoring current custody: worked=%v err=%v", worked, err)
		}
	}
	if interrupt {
		before, err := keys.CreationEvidence(t.Context(), eventprotect.KeyRef{TenantID: tenantA, ID: request.KeyID})
		if err != nil {
			t.Fatal(err)
		}
		if worked, err := box.DispatchOneScoped(actorCtx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || !worked {
			t.Fatalf("retry interrupted preparation: worked=%v err=%v", worked, err)
		}
		after, err := keys.CreationEvidence(t.Context(), eventprotect.KeyRef{TenantID: tenantA, ID: request.KeyID})
		if err != nil || before.Digest() != after.Digest() {
			t.Fatalf("retry changed independent creation identity: %v", err)
		}
	}
	lifetime, err := receiver.Policy.LatestLifetime(t.Context(), tenantA)
	if err != nil || lifetime.Activation == nil {
		t.Fatalf("worker did not retain activation: %v", err)
	}
	creation, err := keys.CreationEvidence(t.Context(), eventprotect.KeyRef{TenantID: tenantA, ID: request.KeyID})
	if err != nil || creation.Digest() != lifetime.Activation.Body.Creation.Digest() {
		t.Fatalf("activation lacks independent creation readback: %v", err)
	}
	activated, found, err := log.EventByID(t.Context(), request.KeyID)
	if err != nil || !found || activated.Actor != nil || activated.Protection != nil {
		t.Fatalf("public activation copied personal attribution or became recursively encrypted: %v", err)
	}
	private, err := record(actorCtx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("aaaaaaaa-0000-0000-0000-000000000001", "private-owner")})
	if err != nil || private.Protection == nil || private.Actor == nil {
		t.Fatalf("activation did not protect subsequent tenant data: %v", err)
	}
	if lateMissingCustody {
		missing, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "late-missing-custody"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: s})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = missing.Close() })
		receiver.Custody = missing
		if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='pending',worker_id=NULL,lease_until=NULL,next_attempt_at=now() WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyPreparationDestination)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if worked, err := box.DispatchOneScoped(actorCtx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || !worked {
			t.Fatalf("retry current activation with missing custody: %v", err)
		}
		if _, err := missing.CreationEvidence(t.Context(), eventprotect.KeyRef{TenantID: tenantA, ID: request.KeyID}); !errors.Is(err, eventprotect.ErrKey) {
			t.Fatalf("active retry regenerated historical key custody: %v", err)
		}
		return
	}
	if worked, err := box.DispatchOneScoped(actorCtx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || worked {
		t.Fatalf("completed intent executed again: worked=%v err=%v", worked, err)
	}
	if err := s.RequireTenantAgentWorkQuiescent(t.Context(), tenantA); err != nil {
		t.Fatalf("successful preparation left an unresolved invocation: %v", err)
	}
}
