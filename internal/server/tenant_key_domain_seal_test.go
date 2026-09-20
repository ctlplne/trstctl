// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type recordingTenantSealCompleter struct {
	calls              int
	failureCalls       int
	tenantID           string
	operationID        string
	failureTenantID    string
	failureOperationID string
}

func (r *recordingTenantSealCompleter) FailSeal(
	_ context.Context,
	tenantID, operationID string,
) (store.TenantKeyDomain, error) {
	r.failureCalls++
	r.failureTenantID = tenantID
	r.failureOperationID = operationID
	return store.TenantKeyDomain{
		TenantID: tenantID, State: store.TenantKeyDomainStatePartial,
		OperationStatus: store.TenantKeyOperationFailed,
	}, nil
}

func (r *recordingTenantSealCompleter) CompleteSeal(
	_ context.Context,
	tenantID, operationID string,
) (store.TenantKeyDomain, error) {
	r.calls++
	r.tenantID = tenantID
	r.operationID = operationID
	return store.TenantKeyDomain{TenantID: tenantID, State: store.TenantKeyDomainStateSealed}, nil
}

func TestTenantKeyDomainSealOutboxRecordsClosedTerminalFailure(t *testing.T) {
	tenantID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	operationID, err := tenantseal.SealOperationID(
		tenantID, "tenant-seal-terminal", "sha256:tenant-seal-terminal",
	)
	if err != nil {
		t.Fatal(err)
	}
	command := store.TenantKeyDomainSealCommand{
		OperationID: operationID, IdempotencyKey: "tenant-seal-terminal",
		RequestBinding: "sha256:tenant-seal-terminal",
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{
		TenantID: tenantID, Destination: store.TenantKeyDomainSealDestination,
		IdempotencyKey: store.TenantKeyDomainSealOutboxKey(operationID), Payload: payload,
	}
	completer := &recordingTenantSealCompleter{}
	dispatcher := &tenantKeyDomainSealOutboxDispatcher{lifecycle: completer}
	handled, err := dispatcher.DeliverTerminalFailure(
		context.Background(), message, errors.New("secret-bearing upstream text"),
	)
	if !handled || err != nil || completer.failureCalls != 1 ||
		completer.failureTenantID != tenantID || completer.failureOperationID != operationID {
		t.Fatalf("terminal delivery = handled %v err %v completer %+v", handled, err, completer)
	}
}

func TestTenantKeyDomainSealOutboxWaitsForCompletedIdempotencyResult(t *testing.T) {
	ctx := context.Background()
	idem := orchestrator.NewMemoryIdempotency()
	completer := &recordingTenantSealCompleter{}
	dispatcher := &tenantKeyDomainSealOutboxDispatcher{idem: idem, lifecycle: completer}
	tenantID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	operationID, err := tenantseal.SealOperationID(
		tenantID, "tenant-seal-1", "sha256:tenant-seal-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	command := store.TenantKeyDomainSealCommand{
		OperationID:    operationID,
		IdempotencyKey: "tenant-seal-1",
		RequestBinding: "sha256:tenant-seal-1",
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{
		TenantID:       tenantID,
		Destination:    store.TenantKeyDomainSealDestination,
		IdempotencyKey: store.TenantKeyDomainSealOutboxKey(command.OperationID),
		Payload:        payload,
	}

	handled, err := dispatcher.Deliver(ctx, message)
	if !handled || !errors.Is(err, orchestrator.ErrIdempotencyNotFound) || completer.calls != 0 {
		t.Fatalf("pre-result delivery = handled %v err %v calls %d", handled, err, completer.calls)
	}
	if _, err := idem.DoDurableEffectBound(
		ctx, message.TenantID, command.IdempotencyKey, command.RequestBinding,
		func(context.Context) ([]byte, error) { return []byte(`{"accepted":true}`), nil },
	); err != nil {
		t.Fatalf("complete accepted result: %v", err)
	}
	handled, err = dispatcher.Deliver(ctx, message)
	if !handled || err != nil || completer.calls != 1 ||
		completer.tenantID != message.TenantID || completer.operationID != command.OperationID {
		t.Fatalf("post-result delivery = handled %v err %v completer %+v", handled, err, completer)
	}
}
