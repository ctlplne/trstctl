// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprotect"
)

// NewDestructionRequest builds the one command for a retained lifetime. It does
// not authorize removal: the worker must still verify current source, retention,
// holds and the committed outbox claim immediately before the custody effect.
func NewDestructionRequest(lifetime Lifetime) (eventprotect.DestructionRequest, error) {
	if lifetime.Activation == nil || lifetime.Offboard == nil || !validIdentity(lifetime.Offboard.ID) {
		return eventprotect.DestructionRequest{}, ErrSource
	}
	activation, offboard := lifetime.Activation, lifetime.Offboard
	expected, err := NewRequested(activation.Meta.TenantID, lifetime.Registration.ID, time.Duration(activation.Body.RetentionNanos))
	if err != nil || expected != activation.Body.Requested() || activation.Meta.ID != expected.KeyID ||
		activation.Body.Creation.Ref.ID != expected.KeyID || activation.Body.Creation.Ref.TenantID != activation.Meta.TenantID ||
		activation.Body.Creation.Digest() == "" || activation.Meta.Sequence == 0 || offboard.Sequence <= activation.Meta.Sequence ||
		offboard.TenantID != activation.Meta.TenantID || offboard.Time.IsZero() || offboard.Time.Before(activation.Meta.Time) {
		return eventprotect.DestructionRequest{}, ErrSource
	}
	operation := crypto.UUIDv5OID([]byte("trstctl.event-key-destruction.v1\x00" + activation.Meta.TenantID + "\x00" + lifetime.Registration.ID + "\x00" + activation.Meta.ID + "\x00" + offboard.ID))
	return eventprotect.DestructionRequest{
		Ref: activation.Body.Creation.Ref, OperationID: operation,
		RegistrationIdentity: lifetime.Registration.ID,
		ActivationEventID:    activation.Meta.ID, ActivationSequence: activation.Meta.Sequence,
		CreationDigest: activation.Body.Creation.Digest(), OffboardEventID: offboard.ID,
		OffboardSequence: offboard.Sequence, OffboardedAt: offboard.Time,
		NotBefore: offboard.Time.Add(time.Duration(activation.Body.RetentionNanos)),
	}, nil
}
