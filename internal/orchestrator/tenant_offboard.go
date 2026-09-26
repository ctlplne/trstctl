// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TenantOffboardCommand binds an authorized erase to one tenant registration.
// RegistrationIdentity is obtained from ResolveLiveTenantRegistrationAuthority
// before authorizing the operation and retained by the caller's durable command
// receiver. It must never be recomputed when retrying that command: the same
// tenant UUID may have been registered again in the meantime.
//
// The caller owns authorization and its request/result binding outside the data
// being erased. This boundary owns the immutable erase event, lifecycle fence,
// SQL projection and recovery after append/commit interruption.
type TenantOffboardCommand struct {
	TenantID             string
	RegistrationIdentity string
}

// OffboardTenant deletes the named registration through the assembled event
// projector, including its transactional lifecycle extensions. Its deterministic
// event identity prevents an old request from erasing a newer registration.
// Exact retries return the retained envelope after the customer SQL receiver has
// itself been erased. Event history and external archives are retained.
func (o *Orchestrator) OffboardTenant(ctx context.Context, command TenantOffboardCommand) (events.Event, error) {
	next, err := tenantOffboardEnvelope(command)
	if err != nil {
		return events.Event{}, err
	}
	return o.emitTenantOffboard(ctx, next)
}

// PrepareTenantOffboard persists the existing core deletion receiver before an
// outer workflow records acceptance. It performs the same preflight and binds
// the same registration and actor as OffboardTenant, but appends no deletion
// event and erases no customer data. The receiver denies service independently
// of licensed attachments until that exact authorized deletion completes.
// A failed outer append does not cancel this durable intent; retry the command.
func (o *Orchestrator) PrepareTenantOffboard(ctx context.Context, command TenantOffboardCommand) error {
	next, err := tenantOffboardEnvelope(command)
	if err != nil {
		return err
	}
	_, err = o.emitTenantOffboardOperation(ctx, next, true)
	return err
}

func tenantOffboardEnvelope(command TenantOffboardCommand) (events.Event, error) {
	if command.TenantID == "" || command.RegistrationIdentity == "" {
		return events.Event{}, errors.New("orchestrator: tenant offboard requires the authorized registration identity")
	}
	return events.Event{
		ID:            projections.TenantOffboardEventID(command.TenantID, command.RegistrationIdentity),
		Type:          projections.EventTenantOffboarded,
		TenantID:      command.TenantID,
		SchemaVersion: events.DefaultSchemaVersion,
		// The legacy event field is not a measured deletion attestation. The
		// projector independently verifies zero SQL residue before committing.
		Data: []byte(`{"rows_deleted":0}`),
	}, nil
}
