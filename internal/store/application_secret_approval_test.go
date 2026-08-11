// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func approveApplicationSecretMutation(
	t *testing.T,
	s *store.Store,
	payload projections.ApplicationSecretMutation,
	requestID, digest, decisionEventID string,
) (projections.ApplicationSecretMutation, store.OperationApprovalRequest) {
	t.Helper()
	if payload.TenantEpoch == "" {
		epoch, err := s.ApplicationSecretTenantEpoch(context.Background(), tenantA)
		if err != nil {
			t.Fatalf("application-secret test tenant epoch: %v", err)
		}
		payload.TenantEpoch = epoch
	}
	if payload.RequestBinding == "" {
		payload.RequestBinding = strings.Repeat("c", 64)
	}
	from, to, evidence, err := projections.ApplicationSecretApprovalBinding(payload)
	if err != nil {
		t.Fatalf("bind application-secret command: %v", err)
	}
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: tenantA, IntentDigest: digest,
		ResourceKind: "secret", ResourceID: "secret:" + payload.Name, ResourceName: payload.Name,
		Action: payload.Action, Requester: "alice", FromState: from, ToState: to,
		TargetVersion:     uint64(payload.ExpectedVersion), // #nosec G115 -- the binding validator proved this fixture version is positive (CWE-190).
		EvidenceRefs:      evidence,
		RequiredApprovals: 1, CreatedAt: operationApprovalBaseTime,
		ExpiresAt: operationApprovalBaseTime.Add(time.Hour),
	}
	if err := applyOperationApprovalRequest(context.Background(), s, request); err != nil {
		t.Fatalf("project application-secret approval request: %v", err)
	}
	if err := applyOperationApprovalDecision(context.Background(), s,
		operationApprovalDecision(request, "bob", decisionEventID)); err != nil {
		t.Fatalf("approve application-secret request: %v", err)
	}
	use := operationApprovalUse(request)
	payload.Approval = &use
	return payload, request
}

func TestPrivacyErasureDeletesUnboundApplicationSecretRequesterFence(t *testing.T) {
	ctx := context.Background()
	s := newOperationApprovalStore(t)
	now := time.Now().UTC()
	ref := privacy.SubjectRef(tenantA, "privacy-alice")
	fence := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "privacy/unbound", Operation: "rotate",
		EventID: "77860000-0000-4000-8000-000000000001", EventType: projections.EventApplicationSecretRotated,
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, ApprovalRequired: true,
		RequesterSealed: []byte("sealed-privacy-alice"), RequesterRef: ref,
		RequestBinding: strings.Repeat("a", 64), Payload: []byte(`{"action":"rotate"}`),
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, fence); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: ref, Counts: map[string]int{}, ErasedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApplicationSecretMutationFence(ctx, tenantA, fence.Name); !store.IsNotFound(err) {
		t.Fatalf("privacy erasure retained decryptable unbound requester fence: %v", err)
	}
}

func TestPrivacyErasureDeletesEveryPreFinalizationApplicationSecretActorFence(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	actor := &events.Actor{Subject: "erase-before-finalize", Roles: []string{"operator"}}
	fixtures := []struct {
		name, operation, eventType, payload string
	}{
		{name: "native/create", operation: "create", eventType: projections.EventApplicationSecretCreated, payload: `{"action":"create"}`},
		{name: "vault/create", operation: "create", eventType: projections.EventApplicationSecretCreated, payload: `{"action":"create"}`},
		{name: "gate-disabled/rotate", operation: "rotate", eventType: projections.EventApplicationSecretRotated, payload: `{"action":"rotate"}`},
	}
	for index, fixture := range fixtures {
		candidate := store.ApplicationSecretMutationFence{
			TenantID: tenantA, Name: fixture.name, Operation: fixture.operation,
			EventID:       fmt.Sprintf("77861000-0000-4000-8000-%012d", index+1),
			EventType:     fixture.eventType,
			SchemaVersion: projections.ApplicationSecretMutationSchemaVersion,
			Actor:         actor, RequestBinding: strings.Repeat(fmt.Sprintf("%x", index+1), 64),
			Payload: []byte(fixture.payload),
		}
		if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
			t.Fatalf("claim %s: %v", fixture.name, err)
		}
	}
	neighbor := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "neighbor/create", Operation: "create",
		EventID:        "77861000-0000-4000-8000-000000000004",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		Actor:          &events.Actor{Subject: "neighbor", Roles: []string{"operator"}},
		RequestBinding: strings.Repeat("a", 64), Payload: []byte(`{"action":"create"}`),
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, neighbor); err != nil {
		t.Fatal(err)
	}
	subjectRef := privacy.SubjectRef(tenantA, actor.Subject)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: subjectRef, Counts: map[string]int{}, ErasedAt: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		if _, err := s.GetApplicationSecretMutationFence(ctx, tenantA, fixture.name); !store.IsNotFound(err) {
			t.Fatalf("pre-finalization %s survived actor erasure: %v", fixture.name, err)
		}
	}
	gotNeighbor, err := s.GetApplicationSecretMutationFence(ctx, tenantA, neighbor.Name)
	if err != nil || !reflect.DeepEqual(gotNeighbor.Actor, neighbor.Actor) {
		t.Fatalf("neighbor fence changed across erasure: %+v err=%v", gotNeighbor, err)
	}
}

func applicationSecretEvent(t *testing.T, id, eventType string, payload projections.ApplicationSecretMutation) events.Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{
		ID: id, Type: eventType, TenantID: tenantA,
		Time:          operationApprovalBaseTime.Add(20 * time.Minute),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
	}
}

func seedApplicationSecretFixture(
	t *testing.T,
	s *store.Store,
	name string,
	sealed []byte,
) store.Secret {
	t.Helper()
	ctx := context.Background()
	var out store.Secret
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version)
			VALUES ($1, $2, $3, 1)
			RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantA, name, sealed).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
			VALUES ($1, $2, 1, $3, $4)`, tenantA, name, sealed, out.UpdatedAt)
		return err
	})
	if err != nil {
		t.Fatalf("seed application-secret fixture %s: %v", name, err)
	}
	out.Sealed = append([]byte(nil), sealed...)
	return out
}

func rotateApplicationSecretFixture(
	t *testing.T,
	s *store.Store,
	name string,
	sealed []byte,
) store.Secret {
	t.Helper()
	ctx := context.Background()
	var out store.Secret
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			UPDATE secret_store
			   SET sealed = $3, version = version + 1, updated_at = now()
			 WHERE tenant_id = $1 AND name = $2
			 RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantA, name, sealed).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
			VALUES ($1, $2, $3, $4, $5)`, tenantA, name, out.Version, sealed, out.UpdatedAt)
		return err
	})
	if err != nil {
		t.Fatalf("rotate application-secret fixture %s: %v", name, err)
	}
	out.Sealed = append([]byte(nil), sealed...)
	return out
}

func TestApplicationSecretMutationRejectsPriorTenantLifecycleEpoch(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	oldEpoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM application_secret_tenant_epochs WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}
	newEpoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if newEpoch == oldEpoch {
		t.Fatal("test fixture did not create a distinct tenant lifecycle epoch")
	}
	mutation := store.ApplicationSecretMutation{
		TenantID: tenantA, TenantEpoch: oldEpoch,
		EventID:        "77910000-0000-4000-8000-000000000001",
		SemanticDigest: strings.Repeat("1", 64), RequestBinding: strings.Repeat("2", 64),
		Action: "create", Name: "old-lifecycle/secret", ResultVersion: 1,
		Sealed: []byte("sealed-old-lifecycle"), OccurredAt: operationApprovalBaseTime,
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyApplicationSecretMutationTx(ctx, tx, mutation)
	})
	if !errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
		t.Fatalf("old-lifecycle mutation error = %v, want ErrApplicationSecretTenantEpochMismatch", err)
	}
	if _, err := s.GetSecret(ctx, tenantA, mutation.Name); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("old-lifecycle event mutated the re-registered tenant: %v", err)
	}
}

func TestStoreExposesNoDirectApplicationSecretMutators(t *testing.T) {
	typ := reflect.TypeOf((*store.Store)(nil))
	for _, method := range []string{"PutSecret", "RotateSecret", "RecoverSecretAt", "PurgeSecret"} {
		if _, ok := typ.MethodByName(method); ok {
			t.Errorf("production Store still exports direct application-secret mutator %s", method)
		}
	}
}

func TestApplicationSecretApprovalConsumeMutationAndReplayAreOneTransaction(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	seedApplicationSecretFixture(t, s, "payments/db", []byte("sealed-v1"))
	payload, request := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "payments/db", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-v2"), IdempotencyKeyDigest: strings.Repeat("a", 64),
		CommandEvidence: strings.Repeat("b", 64), Surface: "native",
	}, "77000000-0000-4000-8000-000000000301", "sha256:secret-rotate", "77000000-0000-4000-8000-000000000302")
	event := applicationSecretEvent(t, "77000000-0000-4000-8000-000000000303",
		projections.EventApplicationSecretRotated, payload)

	// Force the projector's final history insert to fail after it has attempted
	// approval consumption and current-row update. PostgreSQL must roll back all
	// three writes, leaving the immutable event safe for catch-up.
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
		 VALUES ($1, $2, 2, $3, $4)`, tenantA, payload.Name, []byte("conflicting-history"), event.Time); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, event); err == nil {
		t.Fatal("conflicting history unexpectedly committed approved secret mutation")
	}
	current, err := s.GetSecret(ctx, tenantA, payload.Name)
	if err != nil || current.Version != 1 || !bytes.Equal(current.Sealed, []byte("sealed-v1")) {
		t.Fatalf("failed projection partially mutated secret: %+v err=%v", current, err)
	}
	approval, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Status != store.ApprovalStatusApproved || approval.ConsumedEventID != "" {
		t.Fatalf("failed projection spent authority: %+v err=%v", approval, err)
	}
	var receipts int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_mutation_receipts
		  WHERE tenant_id = $1 AND event_id = $2`, tenantA, event.ID).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("failed projection left receipt=%d err=%v, want none", receipts, err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM secret_store_versions WHERE tenant_id = $1 AND name = $2 AND version = 2`, tenantA, payload.Name); err != nil {
		t.Fatal(err)
	}

	// Catch-up of the already-appended target event now heals the gap. Replaying
	// it again recognizes the same consumed event and cannot create version 3.
	projector := projections.New(s)
	if err := projector.Apply(ctx, event); err != nil {
		t.Fatalf("catch up approved secret event: %v", err)
	}
	// JetStream's production duplicate window is not shortened in this harness.
	// Simulate the post-window boundary deterministically: the same canonical
	// envelope/ID/data/time is physically delivered at a distinct stream sequence.
	physicalDuplicate := event
	physicalDuplicate.Sequence = 101
	if err := projector.Apply(ctx, physicalDuplicate); err != nil {
		t.Fatalf("post-dedupe-window physical duplicate poisoned projection: %v", err)
	}
	current, err = s.GetSecret(ctx, tenantA, payload.Name)
	if err != nil || current.Version != 2 || !bytes.Equal(current.Sealed, payload.Sealed) {
		t.Fatalf("caught-up secret = %+v err=%v, want sealed version 2", current, err)
	}
	approval, err = s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Status != store.ApprovalStatusConsumed || approval.ConsumedEventID != event.ID {
		t.Fatalf("caught-up authority = %+v err=%v", approval, err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_mutation_receipts
		  WHERE tenant_id = $1 AND event_id = $2`, tenantA, event.ID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("caught-up receipt=%d err=%v, want one", receipts, err)
	}
	secondEvent := event
	secondEvent.ID = "77000000-0000-4000-8000-000000000304"
	if err := projector.Apply(ctx, secondEvent); !errors.Is(err, store.ErrApprovalConsumed) {
		t.Fatalf("different event reused consumed secret approval = %v, want ErrApprovalConsumed", err)
	}
}

func TestApplicationSecretRecoveryBindsExactSourceAndRejectsTargetDrift(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	seedApplicationSecretFixture(t, s, "recoverable", []byte("sealed-source-v1"))
	source, err := s.GetSecretVersion(ctx, tenantA, "recoverable", 1)
	if err != nil {
		t.Fatal(err)
	}
	rotateApplicationSecretFixture(t, s, "recoverable", []byte("sealed-current-v2"))

	wrong, wrongRequest := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "recover", Name: "recoverable", ExpectedVersion: 2, ResultVersion: 3,
		Sealed: source.Sealed, SourceVersion: source.Version,
		SourceWrittenAt:      source.WrittenAt.Add(time.Nanosecond),
		IdempotencyKeyDigest: strings.Repeat("c", 64), CommandEvidence: strings.Repeat("d", 64), Surface: "native",
	}, "77000000-0000-4000-8000-000000000311", "sha256:secret-recover-wrong", "77000000-0000-4000-8000-000000000312")
	if err := projections.New(s).Apply(ctx, applicationSecretEvent(t,
		"77000000-0000-4000-8000-000000000313", projections.EventApplicationSecretRecovered, wrong)); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("wrong recovery source timestamp = %v, want ErrApprovalDrifted", err)
	}
	wrongApproval, err := s.GetOperationApproval(ctx, tenantA, wrongRequest.ID)
	if err != nil || wrongApproval.Status != store.ApprovalStatusApproved || wrongApproval.ConsumedEventID != "" {
		t.Fatalf("wrong recovery source spent approval: %+v err=%v", wrongApproval, err)
	}

	valid, _ := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "recover", Name: "recoverable", ExpectedVersion: 2, ResultVersion: 3,
		Sealed: source.Sealed, SourceVersion: source.Version, SourceWrittenAt: source.WrittenAt,
		IdempotencyKeyDigest: strings.Repeat("e", 64), CommandEvidence: strings.Repeat("f", 64), Surface: "native",
	}, "77000000-0000-4000-8000-000000000314", "sha256:secret-recover-valid", "77000000-0000-4000-8000-000000000315")
	if err := projections.New(s).Apply(ctx, applicationSecretEvent(t,
		"77000000-0000-4000-8000-000000000316", projections.EventApplicationSecretRecovered, valid)); err != nil {
		t.Fatalf("project exact recovery source: %v", err)
	}
	current, err := s.GetSecret(ctx, tenantA, "recoverable")
	if err != nil || current.Version != 3 || !bytes.Equal(current.Sealed, source.Sealed) {
		t.Fatalf("recovered current = %+v err=%v", current, err)
	}
	history, err := s.GetSecretVersion(ctx, tenantA, "recoverable", 3)
	if err != nil || history.RecoveredFromVersion == nil || *history.RecoveredFromVersion != 1 {
		t.Fatalf("recovery history lost exact source: %+v err=%v", history, err)
	}

	seedApplicationSecretFixture(t, s, "drifted", []byte("sealed-drift-v1"))
	drift, driftRequest := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "drifted", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("approved-but-stale"), IdempotencyKeyDigest: strings.Repeat("1", 64),
		CommandEvidence: strings.Repeat("2", 64), Surface: "native",
	}, "77000000-0000-4000-8000-000000000317", "sha256:secret-target-drift", "77000000-0000-4000-8000-000000000318")
	rotateApplicationSecretFixture(t, s, "drifted", []byte("concurrent-v2"))
	if err := projections.New(s).Apply(ctx, applicationSecretEvent(t,
		"77000000-0000-4000-8000-000000000319", projections.EventApplicationSecretRotated, drift)); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("stale approved target = %v, want ErrApprovalDrifted", err)
	}
	driftApproval, err := s.GetOperationApproval(ctx, tenantA, driftRequest.ID)
	if err != nil || driftApproval.Status != store.ApprovalStatusApproved || driftApproval.ConsumedEventID != "" {
		t.Fatalf("target drift spent approval: %+v err=%v", driftApproval, err)
	}
	driftedCurrent, err := s.GetSecret(ctx, tenantA, "drifted")
	if err != nil || driftedCurrent.Version != 2 || !bytes.Equal(driftedCurrent.Sealed, []byte("concurrent-v2")) {
		t.Fatalf("target drift mutated secret: %+v err=%v", driftedCurrent, err)
	}
}

func TestApplicationSecretMutationFenceOutlivesBrokerDuplicateWindow(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "durable/window", Operation: "create",
		EventID:        "77500000-0000-4000-8000-000000000001",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: strings.Repeat("1", 64),
		Payload:        []byte(`{"action":"create","sealed":"ciphertext"}`),
	}
	claimed, err := s.ClaimApplicationSecretMutationFence(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE application_secret_mutation_fences SET created_at = $3
			  WHERE tenant_id = $1 AND secret_name = $2`, tenantA, candidate.Name, old)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	replayed, err := s.ClaimApplicationSecretMutationFence(ctx, candidate)
	if err != nil {
		t.Fatalf("exact claim expired after 48 hours: %v", err)
	}
	if replayed.EventID != claimed.EventID || !bytes.Equal(replayed.Payload, claimed.Payload) ||
		replayed.CreatedAt.After(old.Add(time.Second)) {
		t.Fatalf("48-hour exact retry did not recover canonical command: first=%+v replay=%+v", claimed, replayed)
	}
	competing := candidate
	competing.EventID = "77500000-0000-4000-8000-000000000002"
	competing.RequestBinding = strings.Repeat("2", 64)
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, competing); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("48-hour fence admitted a competing command: %v", err)
	}
}

func TestApplicationSecretMutationFenceBindsActorAndPrivacyRewritesForRecovery(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	actor := &events.Actor{Subject: "actor-alice", Roles: []string{"operator", "auditor", "operator"}}
	wantActor := &events.Actor{Subject: actor.Subject, Roles: []string{"auditor", "operator"}}
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "durable/actor", Operation: "create",
		EventID:   "77940000-0000-4000-8000-000000000001",
		EventType: projections.EventApplicationSecretCreated, SchemaVersion: projections.ApplicationSecretMutationSchemaVersion,
		Actor: actor, RequestBinding: strings.Repeat("1", 64), Payload: []byte(`{"action":"create"}`),
	}
	claimed, err := s.ClaimApplicationSecretMutationFence(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(claimed.Actor, wantActor) || claimed.ActorSubjectRef != privacy.SubjectRef(tenantA, actor.Subject) {
		t.Fatalf("claim did not persist exact actor/privacy selector: %+v", claimed)
	}
	reordered := candidate
	reordered.Actor = &events.Actor{Subject: actor.Subject, Roles: []string{"auditor", "operator"}}
	if replayed, err := s.ClaimApplicationSecretMutationFence(ctx, reordered); err != nil ||
		!reflect.DeepEqual(replayed.Actor, wantActor) {
		t.Fatalf("same role set in another order did not replay: %+v err=%v", replayed, err)
	}
	drift := candidate
	drift.Actor = &events.Actor{Subject: actor.Subject, Roles: []string{"admin"}}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, drift); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("actor-role drift reused fence: %v", err)
	}
	added := candidate
	added.Actor = &events.Actor{Subject: actor.Subject, Roles: []string{"operator", "auditor", "admin"}}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, added); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("added actor role reused fence: %v", err)
	}
	finalized, err := s.FinalizeApplicationSecretMutationFence(
		ctx, tenantA, candidate.Name, candidate.EventID, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if finalized.Actor == nil || finalized.Actor.Subject != actor.Subject {
		t.Fatalf("finalization lost actor: %+v", finalized)
	}
	subjectRef := privacy.SubjectRef(tenantA, actor.Subject)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: subjectRef, Counts: map[string]int{}, ErasedAt: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatal(err)
	}
	rewritten, err := s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name)
	if err != nil {
		t.Fatal(err)
	}
	wantSubject := privacy.Placeholder(subjectRef)
	if rewritten.Actor == nil || rewritten.Actor.Subject != wantSubject ||
		!reflect.DeepEqual(rewritten.Actor.Roles, wantActor.Roles) || rewritten.ActorSubjectRef != "" ||
		rewritten.EventTime.IsZero() {
		t.Fatalf("privacy rewrite did not preserve recoverable non-PII actor: %+v", rewritten)
	}
}

func TestApplicationSecretMutationFenceRejectsPersistedUnsortedActorRoles(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "durable/unsorted-actor", Operation: "create",
		EventID:        "77940000-0000-4000-8000-000000000011",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: strings.Repeat("7", 64), Payload: []byte(`{"action":"create"}`),
		Actor: &events.Actor{Subject: "actor-alice", Roles: []string{"auditor", "operator"}},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE application_secret_mutation_fences
		SET actor = $3::jsonb
		WHERE tenant_id = $1 AND secret_name = $2`, tenantA, candidate.Name,
		`{"subject":"actor-alice","roles":["operator","auditor"]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name); err == nil ||
		!strings.Contains(err.Error(), "actor roles are not canonical") {
		t.Fatalf("unsorted persisted actor roles error=%v, want canonical-role refusal", err)
	}
}

func TestApplicationSecretFenceRejectsApprovalRequesterDifferentFromActor(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	payload, request := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "actor/requester-drift", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-v2"), IdempotencyKeyDigest: strings.Repeat("1", 64),
		RequestBinding: strings.Repeat("2", 64), CommandEvidence: strings.Repeat("3", 64), Surface: "native",
	}, "77945000-0000-4000-8000-000000000001", "sha256:actor-requester-drift", "77945000-0000-4000-8000-000000000002")
	use := *payload.Approval
	payload.Approval = nil
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: payload.Name, Operation: payload.Action,
		EventID:          "77945000-0000-4000-8000-000000000003",
		EventType:        projections.EventApplicationSecretRotated,
		SchemaVersion:    projections.ApplicationSecretMutationSchemaVersion,
		ApprovalRequired: true,
		RequesterSealed:  []byte("sealed-mallory"), RequesterRef: privacy.SubjectRef(tenantA, "mallory"),
		RequestBinding: payload.RequestBinding, Payload: raw,
		Actor: &events.Actor{Subject: "mallory", Roles: []string{"operator"}},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindApplicationSecretMutationFenceApproval(
		ctx, tenantA, candidate.Name, candidate.EventID, use); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("bind actor/requester drift error=%v, want ErrApprovalDrifted", err)
	}
	if _, err := s.FinalizeApplicationSecretMutationFence(
		ctx, tenantA, candidate.Name, candidate.EventID, &use, operationApprovalBaseTime.Add(10*time.Minute)); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("finalize actor/requester drift error=%v, want ErrApprovalDrifted", err)
	}
	unchanged, err := s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name)
	if err != nil || unchanged.Approval != nil || !unchanged.EventTime.IsZero() {
		t.Fatalf("drifted approval changed durable fence: %+v err=%v", unchanged, err)
	}
	authority, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || authority.Status != store.ApprovalStatusApproved || authority.ConsumedEventID != "" {
		t.Fatalf("drifted approval consumed authority: %+v err=%v", authority, err)
	}
}

func TestApplicationSecretPreCompletionPrivacyRewriteIsAtomicWithExactApprovalRequester(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	payload, request := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "privacy/finalized", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-v2"), IdempotencyKeyDigest: strings.Repeat("a", 64),
		RequestBinding: strings.Repeat("b", 64), CommandEvidence: strings.Repeat("c", 64), Surface: "native",
	}, "77950000-0000-4000-8000-000000000001", "sha256:privacy-finalized", "77950000-0000-4000-8000-000000000002")
	use := *payload.Approval
	payload.Approval = nil
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: payload.Name, Operation: payload.Action,
		EventID:          "77950000-0000-4000-8000-000000000003",
		EventType:        projections.EventApplicationSecretRotated,
		SchemaVersion:    projections.ApplicationSecretMutationSchemaVersion,
		ApprovalRequired: true,
		RequesterSealed:  []byte("sealed-alice"), RequesterRef: privacy.SubjectRef(tenantA, "alice"),
		RequestBinding: payload.RequestBinding, Payload: raw,
		Actor: &events.Actor{Subject: "alice", Roles: []string{"operator", "auditor"}},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	finalized, err := s.FinalizeApplicationSecretMutationFence(
		ctx, tenantA, candidate.Name, candidate.EventID, &use, operationApprovalBaseTime.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if finalized.EventTime.IsZero() {
		t.Fatal("fixture did not cross the finalized point of no return")
	}
	changed, err := s.PseudonymizeApplicationSecretMutationFences(ctx, tenantA, "alice")
	if err != nil || changed != 1 {
		t.Fatalf("pre-completion rewrite changed=%d err=%v", changed, err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, "alice"))
	rewritten, err := s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name)
	if err != nil || rewritten.Actor == nil || rewritten.Actor.Subject != placeholder ||
		!reflect.DeepEqual(rewritten.Actor.Roles, []string{"auditor", "operator"}) ||
		rewritten.ActorSubjectRef != "" || rewritten.EventTime.IsZero() {
		t.Fatalf("finalized fence was not pseudonymized exactly: %+v err=%v", rewritten, err)
	}
	approval, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Requester != placeholder || approval.Status != store.ApprovalStatusConsumed ||
		approval.ConsumedEventID != candidate.EventID {
		t.Fatalf("exact approval was not atomically paired with fence rewrite: %+v err=%v", approval, err)
	}
	gotUse, err := s.ApplicationSecretMutationFenceApprovalUse(ctx, tenantA, rewritten)
	if err != nil || gotUse == nil || gotUse.Requester != placeholder {
		t.Fatalf("recovery did not hydrate only placeholder requester: %+v err=%v", gotUse, err)
	}
	if strings.Contains(string(rewritten.Payload), "alice") || strings.Contains(approval.Requester, "alice") {
		t.Fatal("pre-completion recovery state retained raw requester PII")
	}
}

func TestApplicationSecretRecoveryFencePseudonymizesRoleOnlySubjectWithoutChangingActorIdentity(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	const (
		subject      = "delegated-user@example.com"
		actorSubject = "release-controller"
	)
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "privacy/role-only", Operation: "create",
		EventID:        "77950500-0000-4000-8000-000000000001",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: strings.Repeat("4", 64),
		Payload:        []byte(`{"action":"create","name":"privacy/role-only"}`),
		Actor: &events.Actor{
			Subject: actorSubject,
			Roles:   []string{"operator", "delegate:" + subject, "auditor", "operator"},
		},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinalizeApplicationSecretMutationFence(
		ctx, tenantA, candidate.Name, candidate.EventID, nil, operationApprovalBaseTime.Add(11*time.Minute),
	); err != nil {
		t.Fatal(err)
	}

	changed, err := s.PseudonymizeApplicationSecretMutationFences(ctx, tenantA, subject)
	if err != nil || changed != 1 {
		t.Fatalf("role-only recovery rewrite changed=%d err=%v", changed, err)
	}
	rewritten, err := s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))
	wantRoles := []string{"auditor", "delegate:" + placeholder, "operator"}
	if rewritten.Actor == nil || rewritten.Actor.Subject != actorSubject ||
		!reflect.DeepEqual(rewritten.Actor.Roles, wantRoles) ||
		rewritten.ActorSubjectRef != privacy.SubjectRef(tenantA, actorSubject) {
		t.Fatalf("role-only recovery actor = %+v ref=%q, want subject/ref unchanged and roles %v",
			rewritten.Actor, rewritten.ActorSubjectRef, wantRoles)
	}
}

func TestApplicationSecretRecoveryRoleRewriteRecanonicalizesOrderAndPreservesDuplicateShape(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	const subject = "alice"
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "privacy/role-reorder", Operation: "create",
		EventID:        "77950600-0000-4000-8000-000000000001",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: strings.Repeat("5", 64),
		Payload:        []byte(`{"action":"create","name":"privacy/role-reorder"}`),
		Actor: &events.Actor{
			Subject: "release-controller",
			// The first and third role become the same placeholder. Privacy keeps
			// duplicate cardinality but restores canonical lexical order.
			Roles: []string{subject, "bob", placeholder},
		},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinalizeApplicationSecretMutationFence(
		ctx, tenantA, candidate.Name, candidate.EventID, nil,
		operationApprovalBaseTime.Add(12*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.PseudonymizeApplicationSecretMutationFences(ctx, tenantA, subject); err != nil || changed != 1 {
		t.Fatalf("role reorder rewrite changed=%d err=%v", changed, err)
	}
	wantRoles := []string{"bob", placeholder, placeholder}
	for attempt, load := range []func() (store.ApplicationSecretMutationFence, error){
		func() (store.ApplicationSecretMutationFence, error) {
			return s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name)
		},
		func() (store.ApplicationSecretMutationFence, error) {
			fences, err := s.ListApplicationSecretMutationFences(ctx, tenantA)
			if err != nil || len(fences) != 1 {
				return store.ApplicationSecretMutationFence{}, fmt.Errorf("list fences count=%d: %w", len(fences), err)
			}
			return fences[0], nil
		},
	} {
		rewritten, err := load()
		if err != nil || rewritten.Actor == nil ||
			!reflect.DeepEqual(rewritten.Actor.Roles, wantRoles) {
			t.Fatalf("restart load %d actor=%+v err=%v, want roles=%v", attempt, rewritten.Actor, err, wantRoles)
		}
	}
}

func TestApplicationSecretRecoveryRoleRewritePreservesNonNilEmptyRoles(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	const subject = "empty-role-actor"
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "privacy/empty-role-shape", Operation: "create",
		EventID:        "77950600-0000-4000-8000-000000000002",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: strings.Repeat("6", 64),
		Payload:        []byte(`{"action":"create","name":"privacy/empty-role-shape"}`),
		Actor:          &events.Actor{Subject: subject, Roles: []string{"temporary"}},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinalizeApplicationSecretMutationFence(
		ctx, tenantA, candidate.Name, candidate.EventID, nil,
		operationApprovalBaseTime.Add(13*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	// Model an older writer that explicitly persisted roles:[]; the scanner must
	// preserve that non-nil empty shape through pseudonymization and restart.
	if _, err := s.SystemPool().Exec(ctx, `UPDATE application_secret_mutation_fences
		SET actor = $3::jsonb
		WHERE tenant_id = $1 AND secret_name = $2`, tenantA, candidate.Name,
		`{"subject":"empty-role-actor","roles":[]}`); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.PseudonymizeApplicationSecretMutationFences(ctx, tenantA, subject); err != nil || changed != 1 {
		t.Fatalf("empty-role rewrite changed=%d err=%v", changed, err)
	}
	fences, err := s.ListApplicationSecretMutationFences(ctx, tenantA)
	if err != nil || len(fences) != 1 || fences[0].Actor == nil ||
		fences[0].Actor.Roles == nil || len(fences[0].Actor.Roles) != 0 {
		t.Fatalf("empty role shape after restart = %+v err=%v", fences, err)
	}
}

func TestApplicationSecretPrivacyDeletesApprovedFenceBeforeFinalization(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	payload, request := approveApplicationSecretMutation(t, s, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "privacy/approved-unfinalized", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-v2"), IdempotencyKeyDigest: strings.Repeat("d", 64),
		RequestBinding: strings.Repeat("e", 64), CommandEvidence: strings.Repeat("f", 64), Surface: "native",
	}, "77951000-0000-4000-8000-000000000001", "sha256:privacy-approved-unfinalized", "77951000-0000-4000-8000-000000000002")
	use := *payload.Approval
	payload.Approval = nil
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: payload.Name, Operation: payload.Action,
		EventID:          "77951000-0000-4000-8000-000000000003",
		EventType:        projections.EventApplicationSecretRotated,
		SchemaVersion:    projections.ApplicationSecretMutationSchemaVersion,
		ApprovalRequired: true,
		RequesterSealed:  []byte("sealed-alice"), RequesterRef: privacy.SubjectRef(tenantA, "alice"),
		RequestBinding: payload.RequestBinding, Payload: raw,
		Actor: &events.Actor{Subject: "alice", Roles: []string{"operator"}},
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	bound, err := s.BindApplicationSecretMutationFenceApproval(
		ctx, tenantA, candidate.Name, candidate.EventID, use)
	if err != nil || bound.Approval == nil || !bound.EventTime.IsZero() {
		t.Fatalf("fixture did not stop after approval binding: %+v err=%v", bound, err)
	}
	changed, err := s.PseudonymizeApplicationSecretMutationFences(ctx, tenantA, "alice")
	if err != nil || changed != 1 {
		t.Fatalf("approved unfinalized rewrite changed=%d err=%v", changed, err)
	}
	if _, err := s.GetApplicationSecretMutationFence(ctx, tenantA, candidate.Name); !store.IsNotFound(err) {
		t.Fatalf("approved pre-finalization fence survived privacy completion: %v", err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, "alice"))
	approval, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Requester != placeholder || approval.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("deleted pre-finalization fence left raw/live approval: %+v err=%v", approval, err)
	}
}

func TestApplicationSecretPrivacyBarrierSerializesAcrossStoreInstances(t *testing.T) {
	first := newOperationApprovalStore(t)
	second, err := store.Open(context.Background(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exclusiveEntered := make(chan struct{})
	releaseExclusive := make(chan struct{})
	exclusiveDone := make(chan error, 1)
	go func() {
		exclusiveDone <- store.NewHistoryRewriteCoordinator(first).WithRewriteOperation(ctx, func(context.Context) error {
			close(exclusiveEntered)
			<-releaseExclusive
			return nil
		})
	}()
	select {
	case <-exclusiveEntered:
	case <-ctx.Done():
		t.Fatal("exclusive privacy operation did not acquire its deployment lock")
	}
	sharedEntered := make(chan struct{})
	sharedDone := make(chan error, 1)
	go func() {
		sharedDone <- second.WithApplicationSecretMutationPrivacyBarrier(ctx, tenantA, func(context.Context) error {
			close(sharedEntered)
			return nil
		})
	}()
	select {
	case <-sharedEntered:
		t.Fatal("application-secret append crossed an active privacy completion operation")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseExclusive)
	if err := <-exclusiveDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-sharedEntered:
	case <-ctx.Done():
		t.Fatal("application-secret append barrier did not resume after privacy completion")
	}
	if err := <-sharedDone; err != nil {
		t.Fatal(err)
	}
}

func TestApplicationSecretMutationFenceExactRetryBackfillsLegacyRequesterRef(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	candidate := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "migration/requester-ref", Operation: "rotate",
		EventID: "77500000-0000-4000-8000-000000000011", EventType: projections.EventApplicationSecretRotated,
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, ApprovalRequired: true,
		RequesterSealed: []byte("first-sealed-requester"), RequesterRef: strings.Repeat("a", 64),
		RequestBinding: strings.Repeat("b", 64), Payload: []byte(`{"action":"rotate","sealed":"first-ciphertext"}`),
	}
	claimed, err := s.ClaimApplicationSecretMutationFence(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE application_secret_mutation_fences SET requester_ref = NULL
			  WHERE tenant_id = $1 AND secret_name = $2`, tenantA, candidate.Name)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Exact retries reseal transient material, so the candidate ciphertext may
	// differ. The old canonical command must win while its newly known one-way
	// privacy selector is repaired in place.
	retry := candidate
	retry.RequesterSealed = []byte("retry-sealed-requester")
	retry.Payload = []byte(`{"action":"rotate","sealed":"retry-ciphertext"}`)
	replayed, err := s.ClaimApplicationSecretMutationFence(ctx, retry)
	if err != nil {
		t.Fatalf("exact post-migration retry conflicted: %v", err)
	}
	if replayed.RequesterRef != candidate.RequesterRef ||
		!bytes.Equal(replayed.RequesterSealed, claimed.RequesterSealed) ||
		!bytes.Equal(replayed.Payload, claimed.Payload) {
		t.Fatalf("legacy retry did not preserve/backfill canonical fence: claimed=%+v replayed=%+v", claimed, replayed)
	}
}

func TestApplicationSecretMutationFenceTerminalReplacementAndFinalizedImmutability(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tests := []struct {
		name     string
		terminal string
	}{
		{name: "denied", terminal: store.ApprovalStatusDenied},
		{name: "expired", terminal: store.ApprovalStatusExpired},
		{name: "superseded", terminal: store.ApprovalStatusSuperseded},
		{name: "approved-but-now-expired", terminal: store.ApprovalStatusApproved},
	}
	requestBindingPrefixes := []string{"1", "2", "3", "4"}
	replacementBindingPrefixes := []string{"a", "b", "c", "d"}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := "terminal/" + tc.name
			eventID := fmt.Sprintf("77800000-0000-4000-8000-%012d", index+1)
			requestID := fmt.Sprintf("77810000-0000-4000-8000-%012d", index+1)
			candidate := store.ApplicationSecretMutationFence{
				TenantID: tenantA, Name: name, Operation: "rotate", EventID: eventID,
				EventType:        projections.EventApplicationSecretRotated,
				SchemaVersion:    projections.ApplicationSecretMutationSchemaVersion,
				ApprovalRequired: true, RequesterSealed: []byte("sealed-requester"), RequesterRef: strings.Repeat("1", 64),
				RequestBinding: strings.Repeat(requestBindingPrefixes[index], 64),
				Payload:        []byte(`{"action":"rotate","sealed":"ciphertext"}`),
			}
			if _, err := s.ClaimApplicationSecretMutationFence(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			request := store.OperationApprovalRequest{
				ID: requestID, TenantID: tenantA, IntentDigest: "sha256:" + tc.name,
				ResourceKind: "secret", ResourceID: "secret:" + name, ResourceName: name,
				Action: "rotate", Requester: "alice", FromState: "version:1", ToState: "version:2",
				TargetVersion: 1, RequiredApprovals: 1, CreatedAt: now.Add(-2 * time.Hour),
				ExpiresAt: now.Add(time.Hour),
			}
			if tc.name == "approved-but-now-expired" {
				request.ExpiresAt = now.Add(-30 * time.Minute)
			}
			if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
				t.Fatal(err)
			}
			use := operationApprovalUse(request)
			if _, err := s.BindApplicationSecretMutationFenceApproval(ctx, tenantA, name, eventID, use); err != nil {
				t.Fatal(err)
			}
			switch tc.terminal {
			case store.ApprovalStatusDenied:
				decision := operationApprovalDecision(request, "bob", fmt.Sprintf("77820000-0000-4000-8000-%012d", index+1))
				decision.Decision = store.ApprovalDecisionDeny
				decision.DecidedAt = now.Add(-time.Hour)
				if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
					t.Fatal(err)
				}
			case store.ApprovalStatusExpired, store.ApprovalStatusSuperseded:
				if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					return s.ApplyOperationApprovalStatusTx(ctx, tx, tenantA, request.ID,
						request.IntentDigest, tc.terminal, now)
				}); err != nil {
					t.Fatal(err)
				}
			case store.ApprovalStatusApproved:
				decision := operationApprovalDecision(request, "bob", fmt.Sprintf("77830000-0000-4000-8000-%012d", index+1))
				decision.DecidedAt = now.Add(-time.Hour)
				if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
					t.Fatal(err)
				}
			}
			competing := candidate
			competing.EventID = fmt.Sprintf("77840000-0000-4000-8000-%012d", index+1)
			competing.RequestBinding = strings.Repeat(replacementBindingPrefixes[index], 64)
			competing.RequesterSealed = []byte("new-sealed-requester")
			replacement, err := s.ClaimApplicationSecretMutationFence(ctx, competing)
			if err != nil || replacement.EventID != competing.EventID {
				t.Fatalf("terminal fence was not row-lock replaced: %+v err=%v", replacement, err)
			}
		})
	}

	name := "terminal/finalized"
	request := store.OperationApprovalRequest{
		ID: "77850000-0000-4000-8000-000000000001", TenantID: tenantA,
		IntentDigest: "sha256:finalized", ResourceKind: "secret", ResourceID: "secret:" + name,
		ResourceName: name, Action: "rotate", Requester: "alice", FromState: "version:1", ToState: "version:2",
		TargetVersion: 1, RequiredApprovals: 1, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	decision := operationApprovalDecision(request, "bob", "77850000-0000-4000-8000-000000000002")
	decision.DecidedAt = now.Add(-30 * time.Minute)
	if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
		t.Fatal(err)
	}
	finalized := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: name, Operation: "rotate",
		EventID: "77850000-0000-4000-8000-000000000003", EventType: projections.EventApplicationSecretRotated,
		SchemaVersion:    projections.ApplicationSecretMutationSchemaVersion,
		ApprovalRequired: true, RequesterSealed: []byte("sealed-requester"), RequesterRef: strings.Repeat("2", 64),
		RequestBinding: strings.Repeat("e", 64), Payload: []byte(`{"action":"rotate"}`),
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, finalized); err != nil {
		t.Fatal(err)
	}
	use := operationApprovalUse(request)
	if _, err := s.BindApplicationSecretMutationFenceApproval(ctx, tenantA, name, finalized.EventID, use); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinalizeApplicationSecretMutationFence(ctx, tenantA, name, finalized.EventID, &use, now); err != nil {
		t.Fatal(err)
	}
	reserved, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Status != store.ApprovalStatusConsumed || reserved.ConsumedEventID != finalized.EventID {
		t.Fatalf("finalized fence did not reserve exact approval for its event: %+v", reserved)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalStatusTx(ctx, tx, tenantA, request.ID,
			request.IntentDigest, store.ApprovalStatusExpired, now.Add(2*time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	reserved, err = s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Status != store.ApprovalStatusConsumed || reserved.ConsumedEventID != finalized.EventID {
		t.Fatalf("approval expiry stranded finalized exact command: %+v", reserved)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, use, finalized.EventID, now)
	}); err != nil {
		t.Fatalf("finalized exact command could not resume after terminal status event: %v", err)
	}
	competing := finalized
	competing.EventID = "77850000-0000-4000-8000-000000000004"
	competing.RequestBinding = strings.Repeat("f", 64)
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, competing); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("finalized fence became replaceable after approval expiry: %v", err)
	}
}
