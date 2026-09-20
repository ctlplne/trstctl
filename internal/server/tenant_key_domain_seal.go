// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type tenantKeyDomainSealCompleter interface {
	CompleteSeal(context.Context, string, string) (store.TenantKeyDomain, error)
	FailSeal(context.Context, string, string) (store.TenantKeyDomain, error)
}

// tenantKeyDomainSealOutboxDispatcher owns the zero-egress seal command. It
// does not open the cached HTTP response. It proves only that the authenticated
// result row reached completed, then lets Lifecycle acquire the cross-replica
// exclusive fence and commit sealed.
type tenantKeyDomainSealOutboxDispatcher struct {
	idem      *orchestrator.Idempotency
	lifecycle tenantKeyDomainSealCompleter
}

func (d *tenantKeyDomainSealOutboxDispatcher) Deliver(
	ctx context.Context,
	message orchestrator.Message,
) (bool, error) {
	if message.Destination != store.TenantKeyDomainSealDestination {
		return false, nil
	}
	if d == nil || d.idem == nil || d.lifecycle == nil {
		return true, fmt.Errorf("server: tenant key-domain seal worker is not configured")
	}
	command, err := authenticateTenantKeyDomainSealCommand(message)
	if err != nil {
		return true, err
	}
	completed, err := d.idem.BoundResultCompleted(
		ctx, message.TenantID, command.IdempotencyKey, command.RequestBinding,
	)
	if err != nil {
		return true, err
	}
	if !completed {
		return true, orchestrator.ErrInProgress
	}
	_, err = d.lifecycle.CompleteSeal(ctx, message.TenantID, command.OperationID)
	return true, err
}

// DeliverTerminalFailure replaces an exhausted queue with an immutable visible
// failure before the generic outbox marks the row failed. It intentionally does
// not persist cause.Error(): dependency messages may contain protected bytes.
func (d *tenantKeyDomainSealOutboxDispatcher) DeliverTerminalFailure(
	ctx context.Context,
	message orchestrator.Message,
	_ error,
) (bool, error) {
	if message.Destination != store.TenantKeyDomainSealDestination {
		return false, nil
	}
	if d == nil || d.lifecycle == nil {
		return true, fmt.Errorf("server: tenant key-domain seal worker is not configured")
	}
	command, err := authenticateTenantKeyDomainSealCommand(message)
	if err != nil {
		return true, err
	}
	_, err = d.lifecycle.FailSeal(ctx, message.TenantID, command.OperationID)
	return true, err
}

func authenticateTenantKeyDomainSealCommand(message orchestrator.Message) (store.TenantKeyDomainSealCommand, error) {
	var command store.TenantKeyDomainSealCommand
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		return command, fmt.Errorf("server: decode tenant key-domain seal command: %w", err)
	}
	if message.TenantID == "" || command.OperationID == "" ||
		command.IdempotencyKey == "" || command.RequestBinding == "" ||
		message.IdempotencyKey != store.TenantKeyDomainSealOutboxKey(command.OperationID) {
		return command, fmt.Errorf("server: tenant key-domain seal command is incomplete or misbound")
	}
	expectedID, err := tenantseal.SealOperationID(
		message.TenantID, command.IdempotencyKey, command.RequestBinding,
	)
	if err != nil || expectedID != command.OperationID {
		return command, fmt.Errorf("server: tenant key-domain seal command identity does not authenticate")
	}
	return command, nil
}
