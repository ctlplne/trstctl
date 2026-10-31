// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type destructionReceiverSignerFixture struct {
	key   *jose.SigningKey
	fail  atomic.Bool
	calls atomic.Int64
}

func (s *destructionReceiverSignerFixture) SignArtifact(kind string, data []byte) (string, error) {
	s.calls.Add(1)
	if s.fail.Load() {
		return "", errors.New("fixture signer interrupted after removal")
	}
	return s.key.SignArtifact(kind, data)
}

type expiringDestructionCustody struct {
	*eventprotect.FileAuthority
	expire func(context.Context) error
}

func (c expiringDestructionCustody) WithCustodyFence(ctx context.Context, ref eventprotect.KeyRef, visit func(context.Context) error) error {
	return c.FileAuthority.WithCustodyFence(ctx, ref, func(fenced context.Context) error {
		if err := c.expire(fenced); err != nil {
			return err
		}
		return visit(fenced)
	})
}

// Actual committed SQL claim, NATS, independent custody, source completion and
// generic delivery finalization. The local signing transport fixture does not
// qualify the isolated production signer, runtime assembly or operator routes.
func TestDestructionReceiverRetainsClearanceAcrossRemovalAndSignatureInterruption(t *testing.T) {
	for _, mode := range []string{"normal", "signature-interrupted", "completion-interrupted", "completion-sql-rollback", "claim-expired-before-removal", "new-registration-before-destruction", "older-source-cut-current-receipt", "cleanup-page-after-unverified"} {
		t.Run(mode, func(t *testing.T) { runDestructionReceiverFixture(t, mode) })
	}
}

func runDestructionReceiverFixture(t *testing.T, mode string) {
	s := newStore(t)
	base := t.TempDir()
	locked, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locked.Destroy)
	local, err := jose.NewDigestSigningKey("a233-receiver-component-fixture", locked)
	if err != nil {
		t.Fatal(err)
	}
	remote := &destructionReceiverSignerFixture{key: local}
	signer, err := jose.NewArtifactSigningKey("a233-receiver-component-fixture", locked.Public(), remote)
	if err != nil {
		t.Fatal(err)
	}
	authority := eventprivacy.NewDestructionAuthority()
	cfg := eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "independent-keys"), BackupRoots: []string{filepath.Join(base, "events"), filepath.Join(base, "restored-events")}, Locker: s, EvidenceKey: signer, DestructionAuthority: authority}
	keys, err := eventprotect.NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	policy := &eventprivacy.SourcePolicy{Trust: signer.JWKS()}
	admission := &eventprivacy.SourceAdmission{Guard: s, Custody: keys, Policy: *policy}
	reader := &eventprivacy.SourceKeys{Custody: keys, Policy: *policy}
	preparation := &eventprivacy.PreparationReceiver{Claims: s, Guard: s, Custody: keys, Policy: *policy}
	activationVerifier := &eventprivacy.ActivationVerifier{Custody: keys, Policy: *policy}
	completionVerifier := &eventprivacy.CompletionVerifier{Custody: keys, Policy: *policy}
	receiver := &eventprivacy.DestructionReceiver{Claims: s, Guard: s, Custody: keys, Authority: authority, Policy: *policy}
	p := projections.New(s, projections.WithEventProtectionActivationVerifier(activationVerifier), projections.WithEventProtectionCompletionVerifier(completionVerifier), projections.WithEventProtectionOffboardPolicy(policy))
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")},
		func(log *events.Log) {
			policy.Log = log
			admission.Policy.Log = log
			reader.Policy.Log = log
			preparation.Policy.Log = log
			activationVerifier.Policy.Log = log
			completionVerifier.Policy.Log = log
			receiver.Policy.Log = log
			admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: *policy}
		},
		events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}), events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)), events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	recorder := orchestrator.NewOrchestrator(log, s, nil, orchestrator.WithProjector(p), orchestrator.WithEventProtectionDestructionAuthority(authority))
	interrupted := false
	record := func(ctx context.Context, next events.Event) (events.Event, error) {
		var event events.Event
		err := s.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
			var err error
			event, err = log.Append(ctx, next)
			if err != nil {
				return err
			}
			if next.Type == projections.EventTenantRegistered || next.Type == projections.EventTenantOffboarded {
				return p.ApplyTenantLifecycleTx(ctx, tx, event)
			}
			if err := p.ApplyTx(ctx, tx, event); err != nil {
				return err
			}
			if mode == "completion-sql-rollback" && next.Type == eventprivacy.EventDestroyed && !interrupted {
				interrupted = true
				return errors.New("fixture SQL rollback after terminal source append and token settlement")
			}
			return nil
		})
		return event, err
	}
	preparation.Record = func(ctx context.Context, next events.Event) (events.Event, error) {
		return record(events.ContextWithoutActor(ctx), next)
	}
	receiver.Record = func(ctx context.Context, next events.Event) (events.Event, error) {
		claim, err := authority.ControlClaim(ctx, next)
		if err != nil {
			return events.Event{}, err
		}
		var result events.Event
		err = s.WithEventKeyDestructionClaim(ctx, claim, func(current context.Context) error {
			if mode == "completion-interrupted" && next.Type == eventprivacy.EventDestroyed && !interrupted {
				interrupted = true
				return errors.New("fixture interruption before source completion")
			}
			var err error
			if mode == "completion-sql-rollback" {
				result, err = record(current, next)
			} else {
				result, err = recorder.RecordEventProtectionControl(current, next)
			}
			return err
		})
		return result, err
	}
	actor := events.ContextWithActor(t.Context(), events.Actor{Subject: "fixture-private-operator@example.invalid"})
	registration, err := record(actor, events.Event{TenantID: tenantA, Type: projections.EventTenantRegistered, Data: tenantRegistered("A")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record(actor, events.Event{TenantID: tenantB, Type: projections.EventTenantRegistered, Data: tenantRegistered("B")}); err != nil {
		t.Fatal(err)
	}
	var unverifiedCleanupIDs []int64
	if mode == "cleanup-page-after-unverified" {
		if err := s.WithTenant(t.Context(), tenantB, func(tx pgx.Tx) error {
			for i := 0; i < 16; i++ {
				var id int64
				if err := tx.QueryRow(t.Context(), `INSERT INTO outbox(tenant_id,destination,effect_lane,payload,idempotency_key,required_agent_role,status,delivered_at)
      VALUES($1,$2,$2,$3,$4,'control_plane','delivered',clock_timestamp()) RETURNING id`, tenantB, store.EventKeyDestructionDestination, []byte(`{}`), fmt.Sprintf("unverified-cleanup-fixture-%d", i)).Scan(&id); err != nil {
					return err
				}
				unverifiedCleanupIDs = append(unverifiedCleanupIDs, id)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	requested, err := eventprivacy.NewRequested(tenantA, registration.ID, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(requested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record(actor, events.Event{ID: eventprivacy.RequestedEventID(requested), TenantID: tenantA, Type: eventprivacy.EventRequested, Data: wire}); err != nil {
		t.Fatal(err)
	}
	prepareBox := orchestrator.NewOutbox(s, orchestrator.WithTenantServiceCheck(s.RequireLiveTenantService))
	if worked, err := prepareBox.DispatchOneScoped(actor, orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		var command store.EventKeyPreparationCommand
		if err := json.Unmarshal(m.Payload, &command); err != nil {
			return err
		}
		return preparation.Prepare(ctx, store.EventKeyPreparationClaim{ID: m.ID, Attempts: m.Attempts, AttemptID: m.ReceiverAttemptID, Command: command})
	}), orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || !worked {
		t.Fatalf("preparation: worked=%v err=%v", worked, err)
	}
	private, err := record(actor, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("aaaaaaaa-0000-0000-0000-000000000001", "private-A")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record(actor, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated("aaaaaaaa-0000-0000-0000-000000000001", "private-B")}); err != nil {
		t.Fatal(err)
	}
	// The real hold receiver is qualified separately by the served bucket test.
	// Here retain its complete closed/released source sequence, encrypted under
	// this key, to prove recovery cannot depend on reopening those bodies.
	const hold = "6fcf3d63-8b3f-4397-9b7d-a270f7b81893"
	for _, input := range []struct {
		kind string
		body any
	}{
		{projections.EventArchiveLegalHoldPlaced, projections.ArchiveLegalHoldPlaced{ID: hold, Object: "tenant/" + tenantA + "/audit/fixture.jws", Reason: "fixture source hold"}},
		{projections.EventArchiveLegalHoldRecorded, projections.ArchiveLegalHoldRecorded{ID: hold, Status: "applied", At: time.Now().UTC()}},
		{projections.EventArchiveLegalHoldReleaseRequested, projections.ArchiveLegalHoldRelease{ID: hold}},
		{projections.EventArchiveLegalHoldRecorded, projections.ArchiveLegalHoldRecorded{ID: hold, Status: "released", At: time.Now().UTC()}},
	} {
		data, err := json.Marshal(input.body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := record(actor, events.Event{Type: input.kind, TenantID: tenantA, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	offboard, err := record(actor, events.Event{ID: projections.TenantOffboardEventID(tenantA, registration.ID), Type: projections.EventTenantOffboarded, TenantID: tenantA, Data: []byte(`{"rows_deleted":0}`)})
	if err != nil {
		t.Fatal(err)
	}
	request, protected, err := policy.EventKeyDestructionForOffboard(t.Context(), offboard)
	if err != nil || !protected {
		t.Fatal(err)
	}
	var oldCut uint64
	var oldRecords []events.BackupHistoryRecord
	if mode == "older-source-cut-current-receipt" {
		oldCut, err = log.LastSequence(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := log.ExportBackupHistoryThrough(t.Context(), oldCut, func(record events.BackupHistoryRecord) error {
			record.Stored = bytes.Clone(record.Stored)
			oldRecords = append(oldRecords, record)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var newPrivate events.Event
	var newCreation eventprotect.KeyCreationEvidence
	if mode == "new-registration-before-destruction" {
		newRegistration, err := record(actor, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("new A")})
		if err != nil {
			t.Fatal(err)
		}
		nextRequest, err := eventprivacy.NewRequested(tenantA, newRegistration.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		nextWire, err := json.Marshal(nextRequest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := record(actor, events.Event{ID: eventprivacy.RequestedEventID(nextRequest), Type: eventprivacy.EventRequested, TenantID: tenantA, Data: nextWire}); err != nil {
			t.Fatal(err)
		}
		if worked, err := prepareBox.DispatchOneScoped(actor, orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
			var command store.EventKeyPreparationCommand
			if err := json.Unmarshal(m.Payload, &command); err != nil {
				return err
			}
			return preparation.Prepare(ctx, store.EventKeyPreparationClaim{ID: m.ID, Attempts: m.Attempts, AttemptID: m.ReceiverAttemptID, Command: command})
		}), orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || !worked {
			t.Fatalf("new-lifetime preparation: worked=%v err=%v", worked, err)
		}
		newCreation, err = keys.CreationEvidence(t.Context(), eventprotect.KeyRef{TenantID: tenantA, ID: nextRequest.KeyID})
		if err != nil {
			t.Fatal(err)
		}
		newPrivate, err = record(actor, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("aaaaaaaa-0000-0000-0000-000000000002", "private-new-A")})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The actual record path must reject an otherwise well-formed public
	// control without the package-private grant, before any source append.
	clearanceWire, err := json.Marshal(eventprivacy.HoldClearance{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	beforeControl, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.RecordEventProtectionControl(actor, events.Event{ID: eventprivacy.HoldClearanceEventID(request), Type: eventprivacy.EventHoldClearance, TenantID: tenantA, SchemaVersion: 1, Data: clearanceWire}); err == nil {
		t.Fatal("public control type bypassed deleted-tenant admission without a private claim grant")
	}
	if after, err := log.LastSequence(t.Context()); err != nil || after != beforeControl {
		t.Fatalf("ungranted control changed immutable source: %v", err)
	}
	// An arbitrary call cannot mint an effect grant or publish a control.
	if err := receiver.Destroy(actor, eventprivacy.DestructionClaim{ID: 999999, AttemptID: "fdc5ca32-fb7d-4ea3-b640-fcf032cb0ac5", Attempts: 1, Command: request}); err == nil {
		t.Fatal("missing committed invocation granted destruction")
	}
	if _, err := keys.CreationEvidence(t.Context(), request.Ref); err != nil {
		t.Fatalf("missing claim affected key: %v", err)
	}
	box := orchestrator.NewOutbox(s, orchestrator.WithTenantServiceCheck(s.RequireEventKeyDestructionService), orchestrator.WithBackoff(func(int) time.Duration { return 0 }))
	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		if m.Destination != store.EventKeyDestructionDestination {
			return errors.New("foreign destination")
		}
		var command eventprotect.DestructionRequest
		if err := json.Unmarshal(m.Payload, &command); err != nil {
			return err
		}
		return receiver.Destroy(ctx, eventprivacy.DestructionClaim{ID: m.ID, Attempts: m.Attempts, AttemptID: m.ReceiverAttemptID, Command: command})
	})
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyDestructionDestination}}
	if !time.Now().Before(request.NotBefore) {
		t.Fatal("fixture setup missed its unchanged real retention deadline")
	}
	if worked, err := box.DispatchOneScoped(actor, handler, scope); err != nil || worked {
		t.Fatalf("destruction ran before retention: worked=%v err=%v", worked, err)
	}
	time.Sleep(time.Until(request.NotBefore))
	if mode == "signature-interrupted" {
		remote.fail.Store(true)
	}
	if mode == "claim-expired-before-removal" {
		receiver.Custody = expiringDestructionCustody{FileAuthority: keys, expire: func(ctx context.Context) error {
			return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID))
				return err
			})
		}}
	}

	if worked, err := box.DispatchOneScoped(actor, handler, scope); err != nil || !worked {
		t.Fatalf("first destruction: worked=%v err=%v", worked, err)
	}
	if mode != "normal" && mode != "new-registration-before-destruction" && mode != "older-source-cut-current-receipt" && mode != "cleanup-page-after-unverified" {
		life, found, err := policy.LifetimeForKey(t.Context(), request.Ref)
		if err != nil || !found || life.HoldClearance == nil {
			t.Fatalf("interruption lost public clearance: %v", err)
		}
		if (mode == "completion-sql-rollback") != (life.Completion != nil) {
			t.Fatal("terminal source visibility did not match the interruption boundary")
		}
		if err := s.RequireTenantAgentWorkQuiescent(t.Context(), tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Fatalf("interruption cleared unresolved invocation: %v", err)
		}

		if mode == "claim-expired-before-removal" {
			if _, err := keys.CreationEvidence(t.Context(), request.Ref); err != nil {
				t.Fatalf("expired claim removed key before independent recheck: %v", err)
			}
			if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='pending',worker_id=NULL,lease_until=NULL,next_attempt_at=clock_timestamp() WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := keys.Close(); err != nil {
			t.Fatal(err)
		}
		remote.fail.Store(false)
		keys, err = eventprotect.NewFileAuthority(cfg)
		if err != nil {
			t.Fatal(err)
		}
		admission.Custody, reader.Custody, receiver.Custody, completionVerifier.Custody = keys, keys, keys, keys
		if worked, err := box.DispatchOneScoped(actor, handler, scope); err != nil || !worked {
			t.Fatalf("recover across custody restart: worked=%v err=%v", worked, err)
		}
	}
	if mode == "older-source-cut-current-receipt" {
		// Raw source-cut restoration only, not whole authenticated full-backup
		// qualification. SQL keeps the exact command while its delivery state
		// is reset as a fixture. The current independent custodian is reopened
		// read-only and its signing transport is disabled.
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		if err := keys.Close(); err != nil {
			t.Fatal(err)
		}
		remote.fail.Store(true)
		readOnly := cfg
		readOnly.EvidenceKey = nil
		readOnly.DestructionAuthority = nil
		readOnly.VerificationKeys = signer.JWKS()
		keys, err = eventprotect.NewFileAuthority(readOnly)
		if err != nil {
			t.Fatal(err)
		}
		admission.Custody, reader.Custody, receiver.Custody, completionVerifier.Custody = keys, keys, keys, keys
		restored, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "restored-events")}, func(next *events.Log) {
			policy.Log = next
			admission.Policy.Log = next
			reader.Policy.Log = next
			preparation.Policy.Log = next
			activationVerifier.Policy.Log = next
			completionVerifier.Policy.Log = next
			receiver.Policy.Log = next
			admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: *policy}
		}, events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}), events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)), events.WithRequiredPrivacyEventPolicies())
		if err != nil {
			t.Fatal(err)
		}
		log = restored
		recorder = orchestrator.NewOrchestrator(log, s, nil, orchestrator.WithProjector(p), orchestrator.WithEventProtectionDestructionAuthority(authority))
		var stored bytes.Buffer
		for _, record := range oldRecords {
			stored.Write(record.Stored)
		}
		if _, err := log.RestoreBackupHistory(t.Context(), oldCut, crypto.SHA256Hex(stored.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
			for _, record := range oldRecords {
				if err := yield(record); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		before, found, err := policy.LifetimeForKey(t.Context(), request.Ref)
		if err != nil || !found || before.Completion != nil || before.HoldClearance != nil {
			t.Fatalf("old cut already had later public authority: %v", err)
		}
		if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='pending',worker_id=NULL,lease_until=NULL,next_attempt_at=clock_timestamp() WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if worked, err := box.DispatchOneScoped(actor, handler, scope); err != nil || !worked {
			t.Fatalf("old-cut completion recovery: worked=%v err=%v", worked, err)
		}
		index := 0
		if err := log.ExportBackupHistoryThrough(t.Context(), oldCut, func(record events.BackupHistoryRecord) error {
			if index >= len(oldRecords) || !bytes.Equal(record.Stored, oldRecords[index].Stored) {
				t.Fatal("old-cut recovery rewrote immutable source bytes")
			}
			index++
			return nil
		}); err != nil || index != len(oldRecords) {
			t.Fatalf("old source prefix changed: %v", err)
		}
	}
	life, found, err := policy.LifetimeForKey(t.Context(), request.Ref)
	if err != nil || !found || life.Completion == nil {
		t.Fatalf("completion missing: %v", err)
	}
	if receipt, erased, err := keys.DestructionReceipt(t.Context(), request.Ref); err != nil || !erased || receipt != life.Completion.JWS {
		t.Fatalf("current independent absence missing: %v", err)
	}
	erased, found, err := log.EventByID(t.Context(), private.ID)
	if err != nil || !found || !erased.SensitiveErased || erased.Actor != nil || erased.Data != nil {
		t.Fatalf("private logical source survived destruction: %v", err)
	}
	if err := s.RequireTenantAgentWorkQuiescent(t.Context(), tenantA); err != nil {
		t.Fatalf("verified terminal did not settle old tokens: %v", err)
	}
	publicIDs := []string{life.Completion.Meta.ID}
	if mode == "older-source-cut-current-receipt" {
		if _, found, err := log.EventByID(t.Context(), eventprivacy.HoldClearanceEventID(request)); err != nil || found {
			t.Fatalf("read-only receipt recovery invented hold clearance: %v", err)
		}
	} else {
		publicIDs = append(publicIDs, eventprivacy.HoldClearanceEventID(request))
	}
	for _, id := range publicIDs {
		event, found, err := log.EventByID(t.Context(), id)
		if err != nil || !found || event.Actor != nil || event.Protection != nil || bytes.Contains(event.Data, []byte("example.invalid")) {
			t.Fatalf("public terminal copied private fields: %v", err)
		}
	}
	completion, found, err := log.EventByID(t.Context(), life.Completion.Meta.ID)
	if err != nil || !found {
		t.Fatal(err)
	}
	if mode == "normal" {
		aliased := completion
		aliased.TenantID = "{" + tenantA + "}"
		visited := false
		if err := completionVerifier.WithVerifiedCompletion(t.Context(), aliased, func(context.Context, eventprotect.DestructionRequest) error { visited = true; return nil }); err != nil || !visited {
			t.Fatalf("canonical tenant alias lost retained completion authority: %v", err)
		}
		for name, mutate := range map[string]func(*events.Event){
			"id":        func(e *events.Event) { e.ID += "-changed" },
			"sequence":  func(e *events.Event) { e.Sequence++ },
			"time":      func(e *events.Event) { e.Time = e.Time.Add(time.Nanosecond) },
			"tenant":    func(e *events.Event) { e.TenantID = tenantB },
			"signature": func(e *events.Event) { e.Data = []byte(`{"jws":"invalid"}`) },
			"actor":     func(e *events.Event) { e.Actor = &events.Actor{Subject: "fixture-private@example.invalid"} },
		} {
			t.Run("completion-verification-"+name, func(t *testing.T) {
				changed := completion
				mutate(&changed)
				called := false
				if err := completionVerifier.WithVerifiedCompletion(t.Context(), changed, func(context.Context, eventprotect.DestructionRequest) error { called = true; return nil }); err == nil || called {
					t.Fatal("changed terminal evidence granted SQL settlement")
				}
			})
		}
		missing, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "wrong-current-custody"), BackupRoots: []string{filepath.Join(base, "events"), filepath.Join(base, "restored-events")}, Locker: s, VerificationKeys: signer.JWKS()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = missing.Close() })
		unverified := *completionVerifier
		unverified.Custody = missing
		called := false
		if err := unverified.WithVerifiedCompletion(t.Context(), completion, func(context.Context, eventprotect.DestructionRequest) error { called = true; return nil }); err == nil || called {
			t.Fatal("valid signed source without current independent receipt granted settlement")
		}
	}
	headBeforeCleanup, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	signaturesBeforeCleanup := remote.calls.Load()
	cleanup := &eventprivacy.DestructionCleanup{Store: s, Policy: *policy, Custody: keys}
	if mode == "cleanup-page-after-unverified" {
		removed, err := cleanup.Run(t.Context())
		if err == nil || removed != 0 {
			t.Fatal("unverified delivered rows were treated as destruction evidence")
		}
	}
	removed, err := cleanup.Run(t.Context())
	if err != nil || removed != 1 {
		t.Fatalf("exact finalized intent not cleaned independently: removed=%d err=%v", removed, err)
	}
	headAfterCleanup, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if headAfterCleanup != headBeforeCleanup || remote.calls.Load() != signaturesBeforeCleanup {
		t.Fatal("operational cleanup appended source or requested a new signature")
	}
	if mode == "cleanup-page-after-unverified" {
		var count int
		if err := s.WithTenant(t.Context(), tenantB, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND id=ANY($2::bigint[])`, tenantB, unverifiedCleanupIDs).Scan(&count)
		}); err != nil || count != 16 {
			t.Fatalf("cleanup altered unverified neighbor intents: count=%d err=%v", count, err)
		}
	}
	if newPrivate.ID != "" {
		next, err := policy.LatestLifetime(t.Context(), tenantA)
		if err != nil || next.Activation == nil || next.Activation.Body.Creation.Digest() != newCreation.Digest() || next.Completion != nil {
			t.Fatalf("old completion changed newer lifetime authority: %v", err)
		}
		current, err := keys.CreationEvidence(t.Context(), newCreation.Ref)
		if err != nil || current.Digest() != newCreation.Digest() {
			t.Fatalf("old destruction replaced or removed newer key: %v", err)
		}
		visible, found, err := log.EventByID(t.Context(), newPrivate.ID)
		if err != nil || !found || visible.SensitiveErased || !bytes.Equal(visible.Data, newPrivate.Data) {
			t.Fatalf("old command erased newer logical data: %v", err)
		}
		owners, err := s.ListOwners(t.Context(), tenantA)
		if err != nil || len(owners) != 1 || owners[0].Name != "private-new-A" {
			t.Fatalf("old command erased newer SQL rows: %v", err)
		}
	}
	owners, err := s.ListOwners(t.Context(), tenantB)
	if err != nil || len(owners) != 1 {
		t.Fatalf("neighbor data affected: %v", err)
	}
}
