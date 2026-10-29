// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type ActivationFenceCustody interface {
	ActivationCustody
	WithCustodyFence(context.Context, eventprotect.KeyRef, func(context.Context) error) error
}

// ActivationVerifier grants settlement only from retained source and current
// independent custody, held through the caller's existing SQL projection. It
// retains no key material while that projection runs.
type ActivationVerifier struct {
	Policy  SourcePolicy
	Custody ActivationFenceCustody
}

func (verifier ActivationVerifier) WithVerifiedActivation(ctx context.Context, event events.Event, visit func(context.Context, store.EventKeyPreparationCommand) error) error {
	activation, err := ParseActivated(event)
	if err != nil || verifier.Policy.Log == nil || verifier.Custody == nil || visit == nil {
		return ErrSource
	}
	return verifier.Policy.Log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		life, found, err := verifier.Policy.LifetimeForKey(readCtx, activation.Creation.Ref)
		if err != nil {
			return err
		}
		if !found || life.Request == nil || life.Activation == nil || life.Offboard != nil || life.Activation.Meta.ID != event.ID || life.Activation.Meta.Sequence != event.Sequence || !life.Activation.Meta.Time.Equal(event.Time) {
			return ErrSource
		}
		wire, err := json.Marshal(life.Activation.Body)
		if err != nil || !bytes.Equal(wire, event.Data) {
			return ErrSource
		}
		return verifier.Custody.WithCustodyFence(readCtx, activation.Creation.Ref, func(fenced context.Context) error {
			_, erased, err := verifier.Custody.DestructionReceipt(fenced, activation.Creation.Ref)
			if err != nil {
				return err
			}
			if erased {
				return eventprotect.ErrDestroyed
			}
			creation, err := verifier.Custody.CreationEvidence(fenced, activation.Creation.Ref)
			if err != nil {
				return err
			}
			if creation.Digest() != activation.Creation.Digest() {
				return eventprotect.ErrKey
			}
			return visit(fenced, PreparationCommand(*life.Request))
		})
	})
}
