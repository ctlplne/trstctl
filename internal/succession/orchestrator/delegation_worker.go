// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/delegation"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

type DelegationCustody interface {
	ApplyDelegation(context.Context, delegation.Command) (delegation.Receipt, error)
}

const (
	DelegationScopeDestination = "pcas.delegation-scope"
	DelegationFloorDestination = "pcas.delegation-floor"
)

type DelegationWorker struct {
	repo    *pcasstore.Repo
	log     *events.Log
	custody DelegationCustody
}

func NewDelegationWorker(store *corestore.Store, log *events.Log, custody DelegationCustody) *DelegationWorker {
	return &DelegationWorker{repo: pcasstore.New(store), log: log, custody: custody}
}

// Deliver recovers an ambiguous RPC result by replaying the same operation ID.
// The signer returns its persisted receipt; an exact event ID then fences append
// before the tenant-serving projection is updated.
func (w *DelegationWorker) Deliver(ctx context.Context, m coreorch.Message) error {
	if w.log == nil || w.custody == nil {
		return errors.New("pcas delegation: event log and isolated signer are required")
	}
	var p struct {
		Command  delegation.Command `json:"command"`
		QueuedAt time.Time          `json:"queued_at"`
		Actor    *events.Actor      `json:"actor,omitempty"`
	}
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return err
	}
	if p.Command.TenantID != m.TenantID || p.Command.OperationID == "" || p.QueuedAt.IsZero() ||
		(m.Destination == DelegationScopeDestination && p.Command.Kind != "scope") ||
		(m.Destination == DelegationFloorDestination && p.Command.Kind != "floor") {
		return errors.New("pcas delegation: command does not bind outbox tenant, destination and operation")
	}
	receipt, err := w.custody.ApplyDelegation(ctx, p.Command)
	if err != nil {
		return fmt.Errorf("pcas delegation: signer apply: %w", err)
	}
	if receipt.Command != p.Command || receipt.AppliedFloor != p.Command.EpochFloor {
		return errors.New("pcas delegation: signer receipt does not match queued command")
	}
	if err := receipt.Verify(); err != nil {
		return fmt.Errorf("pcas delegation: signer receipt verification: %w", err)
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	ev, err := succession.Encode(succession.DelegationAppliedV1{
		TenantID: m.TenantID, ReceiptJSON: receiptJSON,
	})
	if err != nil {
		return err
	}
	ev.ID = "pcas-delegation-v1-" + m.TenantID + "-" + p.Command.OperationID
	ev.Time = p.QueuedAt
	ev.Actor = p.Actor
	appended, err := w.log.Append(ctx, ev)
	if err != nil {
		return fmt.Errorf("pcas delegation: append applied event: %w", err)
	}
	return w.repo.ApplyDelegationReceipt(ctx, m.TenantID, appended.Sequence, receipt)
}
