// SPDX-License-Identifier: LicenseRef-trstctl-EE

package remediation_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/canon/reducers"
	"trstctl.com/trstctl/ee/reconcile/plan/remediation"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestRemediationConnector_ScopedToAuthorizedClass proves XREC remediation uses
// a distinct write-scoped connector grant: the exact signer-authorized operation
// class runs, a different operation class is recorded as denied, and the
// observation sandbox remains read-only.
// The remediation connector acts only within its granted classes (XREC-claim-18).
func TestRemediationConnector_ScopedToAuthorizedClass(t *testing.T) {
	ctx := context.Background()
	recorder := newMemoryReceiptRecorder()
	registry := remediation.NewRegistry(recorder)
	writer := &scopedWriteConnector{name: "vault-prod", grant: remediation.NewOperationGrant("rotate-key")}
	registry.Register(writer)
	handler := remediation.NewHandler(registry)

	authorized := remediationJob(t, "rotate-key")
	if err := handler.Deliver(ctx, orchestrator.Message{
		TenantID: authorized.TenantID, Destination: remediation.OutboxDestination,
		IdempotencyKey: authorized.IdempotencyKey, Payload: mustJobPayload(t, authorized),
	}); err != nil {
		t.Fatalf("authorized remediation deliver: %v", err)
	}
	if got := len(writer.executed); got != 1 {
		t.Fatalf("authorized operation executions = %d, want 1", got)
	}
	receipts := recorder.Receipts()
	if len(receipts) != 1 || receipts[0].Status != remediation.ReceiptStatusDelivered || receipts[0].Operation != "rotate-key" {
		t.Fatalf("authorized receipt = %+v, want delivered rotate-key", receipts)
	}

	denied := remediationJob(t, "delete-key")
	if err := handler.Deliver(ctx, orchestrator.Message{
		TenantID: denied.TenantID, Destination: remediation.OutboxDestination,
		IdempotencyKey: denied.IdempotencyKey, Payload: mustJobPayload(t, denied),
	}); err != nil {
		t.Fatalf("out-of-grant remediation deliver should record denial without retry: %v", err)
	}
	if got := len(writer.executed); got != 1 {
		t.Fatalf("out-of-grant operation executed; executions = %d, want still 1", got)
	}
	receipts = recorder.Receipts()
	if len(receipts) != 2 || receipts[1].Status != remediation.ReceiptStatusDenied ||
		receipts[1].Reason != "operation_class_denied" || receipts[1].Operation != "delete-key" {
		t.Fatalf("denied receipt = %+v, want recorded operation-class denial", receipts)
	}

	obsTransport := &trackingObservationTransport{}
	obs := reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant("vault-prod"), obsTransport)
	if _, err := obs.List(ctx, "vault-prod/key-ed25519-prod"); err != nil {
		t.Fatalf("read-only observation list: %v", err)
	}
	if err := obs.Mutate(ctx, "vault-prod/key-ed25519-prod", []byte("must-not-write")); !errors.Is(err, connector.ErrDenied) {
		t.Fatalf("observation mutate = %v, want connector.ErrDenied", err)
	}
	if obsTransport.mutations != 0 {
		t.Fatalf("observation transport mutations = %d, want 0", obsTransport.mutations)
	}
}

func TestRemediationConnector_PreservesConnectorAndReceiptErrors(t *testing.T) {
	connectorErr := errors.New("connector write failed")
	receiptErr := errors.New("receipt persistence failed")
	recorder := &failingReceiptRecorder{err: receiptErr}
	registry := remediation.NewRegistry(recorder)
	registry.Register(&scopedWriteConnector{
		name:  "vault-prod",
		grant: remediation.NewOperationGrant("rotate-key"),
		err:   connectorErr,
	})
	handler := remediation.NewHandler(registry)
	job := remediationJob(t, "rotate-key")

	err := handler.Deliver(context.Background(), orchestrator.Message{
		TenantID: job.TenantID, Destination: remediation.OutboxDestination,
		IdempotencyKey: job.IdempotencyKey, Payload: mustJobPayload(t, job),
	})
	if !errors.Is(err, connectorErr) {
		t.Fatalf("delivery error = %v, want connector cause %v", err, connectorErr)
	}
	if !errors.Is(err, receiptErr) {
		t.Fatalf("delivery error = %v, want receipt cause %v", err, receiptErr)
	}
	if len(recorder.receipts) != 1 {
		t.Fatalf("receipt attempts = %d, want 1", len(recorder.receipts))
	}
	got := recorder.receipts[0]
	if got.Status != remediation.ReceiptStatusFailed || got.Reason != "connector_failed" ||
		!strings.Contains(got.Detail, connectorErr.Error()) {
		t.Fatalf("failed receipt = %+v, want connector failure evidence", got)
	}
}

type scopedWriteConnector struct {
	name     string
	grant    remediation.OperationGrant
	executed []remediation.RemediationRequest
	err      error
}

func (c *scopedWriteConnector) Name() string { return c.name }

func (c *scopedWriteConnector) OperationGrant() remediation.OperationGrant { return c.grant }

func (c *scopedWriteConnector) ExecuteRemediationAction(_ context.Context, req remediation.RemediationRequest) (string, error) {
	c.executed = append(c.executed, req)
	if c.err != nil {
		return "", c.err
	}
	return "rotated " + req.RecordKey.StableID, nil
}

type trackingObservationTransport struct {
	mutations int
}

func (t *trackingObservationTransport) DoObservation(_ context.Context, op reducers.AuthorityOperation) ([]byte, error) {
	if op.Kind == reducers.OpMutate {
		t.mutations++
	}
	return []byte("ok"), nil
}

func remediationJob(t *testing.T, operation string) remediation.Job {
	t.Helper()
	recordKey := canon.RecordKey{
		TenantID:   tenantA,
		RecordType: canon.RecordTypeKey,
		StableID:   "key-ed25519-prod",
	}
	idem, err := remediation.StableIdempotencyKey([]byte("witness-hash-"+operation), recordKey, operation)
	if err != nil {
		t.Fatalf("idempotency key: %v", err)
	}
	return remediation.Job{
		TenantID:    tenantA,
		PlanID:      "plan-09c",
		PlanHash:    "plan-hash",
		WitnessID:   "witness-09c",
		WitnessHash: "witness-hash-" + operation,
		AuthorityID: "vault-prod",
		RecordKey:   recordKey,
		Operation:   operation,
		Parameters: map[string]string{
			"target": "vault-prod/key-ed25519-prod",
		},
		Authorization:  []byte(`{"approved":true}`),
		IdempotencyKey: idem,
	}
}

func mustJobPayload(t *testing.T, job remediation.Job) []byte {
	t.Helper()
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	return raw
}

type memoryReceiptRecorder struct {
	mu       sync.Mutex
	receipts []remediation.Receipt
}

func newMemoryReceiptRecorder() *memoryReceiptRecorder { return &memoryReceiptRecorder{} }

func (r *memoryReceiptRecorder) RecordRemediationReceipt(_ context.Context, receipt remediation.Receipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	receipt.RecordedAt = time.Now().UTC()
	r.receipts = append(r.receipts, receipt)
	return nil
}

func (r *memoryReceiptRecorder) Receipts() []remediation.Receipt {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]remediation.Receipt, len(r.receipts))
	copy(out, r.receipts)
	return out
}

type failingReceiptRecorder struct {
	err      error
	receipts []remediation.Receipt
}

func (r *failingReceiptRecorder) RecordRemediationReceipt(_ context.Context, receipt remediation.Receipt) error {
	r.receipts = append(r.receipts, receipt)
	return r.err
}
