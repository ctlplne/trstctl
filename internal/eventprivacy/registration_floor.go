// SPDX-License-Identifier: BUSL-1.1
package eventprivacy

import (
	"context"
	"time"
	"trstctl.com/trstctl/internal/eventprotect"
)

type registrationCustody interface {
	WithCustodyFence(context.Context, eventprotect.KeyRef, func(context.Context) error) error
	LookupKeyState(context.Context, eventprotect.KeyRef) (eventprotect.CurrentKeyState, bool, error)
}
type registrationFloor struct {
	found, erased bool
	ref           eventprotect.KeyRef
	receipt       string
}

// withRegistrationFloor checks CURRENT custody for a FIRST source registration
// whose older cut has no activation yet. Signed absence is a read/admission floor,
// never a destructive grant or a fabricated historical control. Sequence numbers
// alone cannot choose the cut: a restored prefix can grow along another branch.
func (policy SourcePolicy) withRegistrationFloor(ctx context.Context, life Lifetime, custody any, visit func(context.Context, registrationFloor) error) error {
	if visit == nil {
		return ErrSource
	}
	if life.Activation != nil || life.Registration.ID == "" || custody == nil {
		return visit(ctx, registrationFloor{})
	}
	reader, ok := custody.(registrationCustody)
	if !ok {
		return ErrSource
	}
	request, err := NewRequested(life.Registration.TenantID, life.Registration.ID, time.Nanosecond)
	if err != nil {
		return err
	}
	ref := eventprotect.KeyRef{TenantID: life.Registration.TenantID, ID: request.KeyID}
	return reader.WithCustodyFence(ctx, ref, func(fenced context.Context) error {
		state, found, err := reader.LookupKeyState(fenced, ref)
		if err != nil {
			return err
		}
		if !found {
			return visit(fenced, registrationFloor{})
		}
		floor := registrationFloor{found: true, ref: ref}
		if state.Creation.Ref != ref {
			return ErrSource
		}
		switch state.Phase {
		case eventprotect.CustodyKeyPreparing, eventprotect.CustodyKeyActive:
			return visit(fenced, floor)
		case eventprotect.CustodyKeyPending:
			return eventprotect.ErrKey
		case eventprotect.CustodyKeyDestroyed:
			claims, err := policy.verifyDestructionReceipt(state.Receipt)
			if err != nil {
				return err
			}
			command := claims.Request
			if command.Validate() != nil || command.Ref != ref || command.RegistrationIdentity != life.Registration.ID || command.ActivationEventID != ref.ID || command.CreationDigest != state.Creation.Digest() || state.Creation.CreatedAt.Before(life.Registration.Time) || state.Creation.CreatedAt.After(command.OffboardedAt) || claims.RemovedAt.Before(command.NotBefore) {
				return ErrSource
			}
			if life.Request != nil {
				if life.Request.Body.KeyID != ref.ID || life.Request.Body.OperationID != ref.ID || !command.NotBefore.Equal(command.OffboardedAt.Add(time.Duration(life.Request.Body.RetentionNanos))) {
					return ErrSource
				}
			}
			if life.Offboard != nil && (life.Offboard.ID != command.OffboardEventID || life.Offboard.Sequence != command.OffboardSequence || !life.Offboard.Time.Equal(command.OffboardedAt)) {
				return ErrSource
			}
			floor.erased, floor.receipt = true, state.Receipt
			return visit(fenced, floor)
		default:
			return eventprotect.ErrKey
		}
	})
}
