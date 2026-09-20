// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type durableRightSizeMutator struct {
	calls int
	err   error
}

func (m *durableRightSizeMutator) Mutate(context.Context, orchestrator.Message, projections.RemediationPlaybookRunRecorded) (RightSizeMutation, error) {
	m.calls++
	if m.err != nil {
		return RightSizeMutation{}, m.err
	}
	return RightSizeMutation{MutationID: "mutation-1", RollbackRef: "rollback-1", ReadbackDigest: "digest-1"}, nil
}

func TestConnectorRightSizeDurableWorkerCrashReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS")
	}
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)
	mutator := &durableRightSizeMutator{}
	h.handler.connectorRightSize = mutator

	// Crash after the receiver changed state but before a terminal event. The
	// retry uses the same receiver key, then commits one deterministic terminal
	// receipt; another redelivery observes terminal state and performs no I/O.
	message := seedDurableRightSizeOperation(t, h, "right-size-side-effect-crash")
	injected := errors.New("injected crash after receiver side effect")
	h.handler.afterRightSizeSideEffects = func(context.Context) error { return injected }
	if err := h.handler.handleConnectorRightSize(ctx, message); !errors.Is(err, injected) {
		t.Fatalf("first delivery error = %v, want injected crash", err)
	}
	assertDurableRightSizeState(t, h, message, "queued", "queued")
	h.handler.afterRightSizeSideEffects = nil
	message.Attempts = 2
	if err := h.handler.handleConnectorRightSize(ctx, message); err != nil {
		t.Fatalf("retry delivery: %v", err)
	}
	assertDurableRightSizeState(t, h, message, "succeeded", "delivered")
	message.Attempts = 3
	if err := h.handler.handleConnectorRightSize(ctx, message); err != nil {
		t.Fatalf("terminal reconciliation delivery: %v", err)
	}
	if mutator.calls != 2 {
		t.Fatalf("receiver calls after terminal redelivery = %d, want 2", mutator.calls)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, message.ID)
		return err
	}); err != nil {
		t.Fatalf("collect terminal outbox row: %v", err)
	}
	if healed, err := h.orch.ReconcileOutbox(ctx, h.log); err != nil || healed != 1 {
		t.Fatalf("reconcile collected right-size outbox = healed %d err %v, want 1/nil", healed, err)
	}
	message = loadDurableRightSizeMessage(t, h, "right-size-side-effect-crash")
	if err := h.handler.handleConnectorRightSize(ctx, message); err != nil {
		t.Fatalf("recreated terminal outbox delivery: %v", err)
	}
	if mutator.calls != 2 {
		t.Fatalf("receiver calls after outbox reconciliation = %d, want 2", mutator.calls)
	}

	// Crash after JetStream accepted the terminal event but before its projection.
	// A retry may safely read back the receiver again; the duplicate event ID
	// resolves to the canonical first event and advances the queued row once.
	message = seedDurableRightSizeOperation(t, h, "right-size-terminal-append-crash")
	injected = errors.New("injected crash after terminal append")
	h.handler.afterRightSizeTerminalAppend = func(context.Context) error { return injected }
	if err := h.handler.handleConnectorRightSize(ctx, message); !errors.Is(err, injected) {
		t.Fatalf("terminal append crash error = %v, want injected", err)
	}
	assertDurableRightSizeState(t, h, message, "queued", "queued")
	h.handler.afterRightSizeTerminalAppend = nil
	message.Attempts = 2
	if err := h.handler.handleConnectorRightSize(ctx, message); err != nil {
		t.Fatalf("terminal append retry: %v", err)
	}
	assertDurableRightSizeState(t, h, message, "succeeded", "delivered")
	identity := rightSizeIdentityFromMessage(t, message)
	terminalEvents := 0
	if err := h.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.ID == identity.TerminalEventID {
			terminalEvents++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay terminal events: %v", err)
	}
	if terminalEvents != 1 {
		t.Fatalf("terminal events = %d, want one deterministic event", terminalEvents)
	}

	// Exhausted retries close the domain state with a stable public reason. The
	// raw receiver error is deliberately absent from both receipt and run.
	message = seedDurableRightSizeOperation(t, h, "right-size-terminal-failure")
	mutator.err = errors.New("provider-secret-token=do-not-retain")
	message.Attempts = 5
	deliveryErr := h.handler.handleConnectorRightSize(ctx, message)
	if deliveryErr == nil {
		t.Fatal("receiver failure unexpectedly succeeded")
	}
	if err := h.handler.DeliverTerminalFailure(ctx, message, deliveryErr); err != nil {
		t.Fatalf("record terminal failure: %v", err)
	}
	run, receipt := assertDurableRightSizeState(t, h, message, "failed", "failed")
	if run.TerminalReason != "entitlement_mutation_retry_exhausted" ||
		strings.Contains(receipt.Detail, "provider-secret-token") || strings.Contains(run.TerminalReason, "provider-secret-token") {
		t.Fatalf("terminal failure retained raw receiver data: run=%+v receipt=%+v", run, receipt)
	}
}

func seedDurableRightSizeOperation(t *testing.T, h *issuanceDispatcherHarness, key string) orchestrator.Message {
	t.Helper()
	const targetIdentityID = "10000000-0000-4000-8000-000000000001"
	identity := orchestrator.ConnectorRightSizeIdentityFor(h.tenant, key)
	deliveryID := identity.DeliveryID
	_, err := h.orch.RecordConnectorRightSizeOperation(context.Background(), h.tenant, store.RemediationPlaybookRun{
		ID: identity.OperationID, PlaybookID: "nhi-right-size", TargetIdentityID: targetIdentityID,
		InventoryID: "identity/" + targetIdentityID, Status: "queued", Phase: "right_size_connector_intent_queued",
		Action: "right_size", Reason: "usage-backed right-size", Connector: "least-privilege", Target: "service-1",
		ConnectorDeliveryID: &deliveryID,
		ScopeDelta:          json.RawMessage(`{"remove_scopes":["write"],"recommended_scopes":["read"]}`),
		EvidenceRefs:        []string{"nhi_posture:CAP-POST-01"}, RollbackRefs: []string{"restore write"},
		IdempotencyKey: key, RequestBinding: "binding-" + key,
		InitialHTTPStatus: 201, InitialResponse: json.RawMessage(`{"status":"queued"}`), CreatedBy: "operator",
	})
	if err != nil {
		t.Fatalf("record durable right-size operation: %v", err)
	}
	return loadDurableRightSizeMessage(t, h, key)
}

func loadDurableRightSizeMessage(t *testing.T, h *issuanceDispatcherHarness, key string) orchestrator.Message {
	t.Helper()
	identity := orchestrator.ConnectorRightSizeIdentityFor(h.tenant, key)
	var message orchestrator.Message
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT id, tenant_id::text, destination, idempotency_key, payload, attempts, effect_lane
			   FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			h.tenant, identity.OutboxIdempotencyKey).Scan(
			&message.ID, &message.TenantID, &message.Destination, &message.IdempotencyKey,
			&message.Payload, &message.Attempts, &message.EffectLane)
	}); err != nil {
		t.Fatalf("load durable right-size outbox: %v", err)
	}
	message.Attempts = 1
	return message
}

func rightSizeIdentityFromMessage(t *testing.T, message orchestrator.Message) orchestrator.ConnectorRightSizeIdentity {
	t.Helper()
	var payload projections.RemediationPlaybookRunRecorded
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return orchestrator.ConnectorRightSizeIdentityFor(message.TenantID, payload.IdempotencyKey)
}

func assertDurableRightSizeState(t *testing.T, h *issuanceDispatcherHarness, message orchestrator.Message, runStatus, receiptStatus string) (store.RemediationPlaybookRun, store.ConnectorDeliveryReceipt) {
	t.Helper()
	identity := rightSizeIdentityFromMessage(t, message)
	run, err := h.store.GetRemediationPlaybookRun(context.Background(), h.tenant, identity.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := h.store.GetConnectorDeliveryReceipt(context.Background(), h.tenant, identity.DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != runStatus || receipt.Status != receiptStatus {
		t.Fatalf("durable right-size state = run %q receipt %q, want %q/%q", run.Status, receipt.Status, runStatus, receiptStatus)
	}
	return run, receipt
}
