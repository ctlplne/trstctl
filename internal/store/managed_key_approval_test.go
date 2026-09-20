// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func managedKeyApprovalCommand(t *testing.T, operationID, requestBinding string) projections.ManagedKeyCommand {
	t.Helper()
	command := projections.ManagedKeyCommand{
		OperationID: operationID, Provider: "aws-kms", Action: "revoke",
		KeyID: "kms/root-signing", Algorithm: "ECDSA-P256", RequestBinding: requestBinding,
		Requester: "alice", FromState: "active", ToState: "revoked", TargetVersion: 4,
		IdempotencyKeyDigest: "75eafc2f88a8c718965ffd6972db4d4e8f5d17f59013b0d36edec1918993f48d",
	}
	evidence, err := projections.ManagedKeyApprovalEvidence(command)
	if err != nil {
		t.Fatalf("build managed-key command evidence: %v", err)
	}
	command.ApprovalEvidenceRefs = evidence
	return command
}

func approvedManagedKeyRequest(t *testing.T, s *store.Store, command projections.ManagedKeyCommand, requestID, digest string) store.OperationApprovalRequest {
	t.Helper()
	ctx := context.Background()
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: tenantA, IntentDigest: digest,
		ResourceKind: "managed_key", ResourceID: command.KeyID, ResourceName: command.KeyID,
		Action: "managedkey:" + command.Action, Requester: command.Requester,
		FromState: command.FromState, ToState: command.ToState, TargetVersion: command.TargetVersion,
		EvidenceRefs: command.ApprovalEvidenceRefs, RequiredApprovals: 1,
		CreatedAt: operationApprovalBaseTime, ExpiresAt: operationApprovalBaseTime.Add(time.Hour),
	}
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatalf("project managed-key approval request: %v", err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000191")); err != nil {
		t.Fatalf("approve managed-key request: %v", err)
	}
	return request
}

func seedManagedKeyApprovalTarget(t *testing.T, s *store.Store) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`INSERT INTO managed_keys
		       (tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at)
		 VALUES ($1, 'aws-kms', 'kms/root-signing', 'ECDSA-P256', 4, 'active', $2, now(), now())`,
		tenantA, []byte("public-key")); err != nil {
		t.Fatalf("seed managed-key approval target: %v", err)
	}
}

func TestManagedKeyCommandConsumesExactApprovalBesideOperationAndOutbox(t *testing.T) {
	s := newOperationApprovalStore(t)
	seedManagedKeyApprovalTarget(t, s)
	ctx := context.Background()
	command := managedKeyApprovalCommand(t, "managedkey:approved-operation", "sha256:approved-command-binding")
	request := approvedManagedKeyRequest(t, s, command,
		"77000000-0000-4000-8000-000000000090", "sha256:managed-key-approved-intent")
	use := operationApprovalUse(request)
	command.Approval = &use
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID: "77000000-0000-4000-8000-000000000192", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: operationApprovalBaseTime.Add(20 * time.Minute),
		SchemaVersion: projections.ManagedKeyApprovalEventSchemaVersion, Data: payload,
	}
	projector := projections.New(s)
	if err := projector.Apply(ctx, event); err != nil {
		t.Fatalf("project approved managed-key command: %v", err)
	}

	consumed, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID != event.ID {
		t.Fatalf("consumed approval = (%+v, %v), want event %s", consumed, err, event.ID)
	}
	op, err := s.GetManagedKeyOperation(ctx, tenantA, command.OperationID)
	if err != nil || op.Status != "queued" || op.RequestBinding != command.RequestBinding {
		t.Fatalf("managed-key operation = (%+v, %v), want queued exact command", op, err)
	}
	var outboxRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, command.OperationID).Scan(&outboxRows); err != nil || outboxRows != 1 {
		t.Fatalf("managed-key outbox rows = %d err=%v, want one", outboxRows, err)
	}

	// The operation may already have completed when an at-least-once projector
	// sees the requested event again. Exact consumed-event replay must not mistake
	// that legitimate result state for target drift or enqueue another effect.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE managed_keys SET state = 'revoked' WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`,
		tenantA, command.Provider, command.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, event); err != nil {
		t.Fatalf("replay exact consumed managed-key event: %v", err)
	}
	secondUse := event
	secondUse.ID = "77000000-0000-4000-8000-000000000195"
	if err := projector.Apply(ctx, secondUse); !errors.Is(err, store.ErrApprovalConsumed) {
		t.Fatalf("second event reused managed-key approval = %v, want ErrApprovalConsumed", err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, command.OperationID).Scan(&outboxRows); err != nil || outboxRows != 1 {
		t.Fatalf("replay managed-key outbox rows = %d err=%v, want one", outboxRows, err)
	}
}

func TestManagedKeyApprovalConsumptionRollsBackWhenOutboxIntentConflicts(t *testing.T) {
	s := newOperationApprovalStore(t)
	seedManagedKeyApprovalTarget(t, s)
	ctx := context.Background()
	command := managedKeyApprovalCommand(t, "managedkey:conflicting-operation", "sha256:conflicting-command-binding")
	command.IdempotencyKeyDigest = "7f47785e8b3960fda4c5f16747af80e5a1a030d1b271359181ede789957744f5"
	evidence, err := projections.ManagedKeyApprovalEvidence(command)
	if err != nil {
		t.Fatal(err)
	}
	command.ApprovalEvidenceRefs = evidence
	request := approvedManagedKeyRequest(t, s, command,
		"77000000-0000-4000-8000-000000000091", "sha256:managed-key-rollback-intent")
	use := operationApprovalUse(request)
	command.Approval = &use
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1, 'webhook', $2, $3)`, tenantA, []byte(`{"foreign":true}`), command.OperationID); err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID: "77000000-0000-4000-8000-000000000193", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: operationApprovalBaseTime.Add(20 * time.Minute),
		SchemaVersion: projections.ManagedKeyApprovalEventSchemaVersion, Data: payload,
	}
	if err := projections.New(s).Apply(ctx, event); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("conflicting outbox projection = %v, want pgx.ErrNoRows", err)
	}
	approval, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Status != store.ApprovalStatusApproved || approval.ConsumedEventID != "" {
		t.Fatalf("rolled-back approval = (%+v, %v), want still approved", approval, err)
	}
	if _, err := s.GetManagedKeyOperation(ctx, tenantA, command.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("conflicting command operation = %v, want no row", err)
	}
}

func TestManagedKeyApprovalRefusesProjectedTargetVersionDrift(t *testing.T) {
	s := newOperationApprovalStore(t)
	seedManagedKeyApprovalTarget(t, s)
	ctx := context.Background()
	command := managedKeyApprovalCommand(t, "managedkey:stale-target", "sha256:stale-target-binding")
	request := approvedManagedKeyRequest(t, s, command,
		"77000000-0000-4000-8000-000000000092", "sha256:managed-key-stale-target-intent")
	use := operationApprovalUse(request)
	command.Approval = &use
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE managed_keys SET version = 5 WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`,
		tenantA, command.Provider, command.KeyID); err != nil {
		t.Fatal(err)
	}
	err = projections.New(s).Apply(ctx, events.Event{
		ID: "77000000-0000-4000-8000-000000000196", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: operationApprovalBaseTime.Add(20 * time.Minute),
		SchemaVersion: projections.ManagedKeyApprovalEventSchemaVersion, Data: payload,
	})
	if !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("stale managed-key target version = %v, want ErrApprovalDrifted", err)
	}
	approval, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Status != store.ApprovalStatusApproved || approval.ConsumedEventID != "" {
		t.Fatalf("stale target consumed authority = (%+v, %v), want still approved", approval, err)
	}
	if _, err := s.GetManagedKeyOperation(ctx, tenantA, command.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale target operation = %v, want no row", err)
	}
}

func TestManagedKeyDestructiveCommandWithoutExactApprovalFailsClosed(t *testing.T) {
	s := newOperationApprovalStore(t)
	seedManagedKeyApprovalTarget(t, s)
	command := managedKeyApprovalCommand(t, "managedkey:no-approval", "sha256:no-approval-command-binding")
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	err = projections.New(s).Apply(context.Background(), events.Event{
		ID: "77000000-0000-4000-8000-000000000194", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: operationApprovalBaseTime.Add(20 * time.Minute),
		SchemaVersion: projections.ManagedKeyApprovalEventSchemaVersion, Data: payload,
	})
	if !errors.Is(err, store.ErrApprovalNotReady) {
		t.Fatalf("destructive command without exact authority = %v, want ErrApprovalNotReady", err)
	}
	if _, err := s.GetManagedKeyOperation(context.Background(), tenantA, command.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unapproved destructive operation = %v, want no row", err)
	}
}

func TestManagedKeyLegacyDestructiveCommandSchemaCannotBypassApproval(t *testing.T) {
	s := newOperationApprovalStore(t)
	seedManagedKeyApprovalTarget(t, s)
	command := projections.ManagedKeyCommand{
		OperationID: "managedkey:legacy-standing-permission", Provider: "aws-kms",
		Action: "revoke", KeyID: "kms/root-signing", Algorithm: "ECDSA-P256",
		RequestBinding: "sha256:legacy-boolean-binding",
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	err = projections.New(s).Apply(context.Background(), events.Event{
		ID: "77000000-0000-4000-8000-000000000197", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: operationApprovalBaseTime.Add(20 * time.Minute),
		SchemaVersion: events.DefaultSchemaVersion, Data: payload,
	})
	if !errors.Is(err, store.ErrApprovalNotReady) {
		t.Fatalf("legacy destructive command schema = %v, want ErrApprovalNotReady", err)
	}
	if _, err := s.GetManagedKeyOperation(context.Background(), tenantA, command.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("legacy destructive operation = %v, want no row", err)
	}
}
