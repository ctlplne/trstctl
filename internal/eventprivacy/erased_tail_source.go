// SPDX-License-Identifier: BUSL-1.1
package eventprivacy

import (
	"context"
	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// WithRetainedSource checks one actual tail message against retained metadata
// and one finite tenant lifetime fold. It keeps no cached erasure grant and
// never holds the history fence for an infinite worker.
func (planner ErasurePlanner) WithRetainedSource(ctx context.Context, event events.Event, visit func(context.Context, bool) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if planner.Policy.Log == nil || visit == nil || event.Sequence == 0 {
		return ErrSource
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil {
		return visit(ctx, false)
	}
	return planner.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		head, err := planner.Policy.Log.LastSequence(read)
		if err != nil {
			return err
		}
		if event.Sequence > head {
			return ErrSource
		}
		found := false
		if err := planner.Policy.Log.ReplayTenantMetadataTypesThrough(read, tenant.String(), event.Sequence, event.Sequence, []string{event.Type}, func(meta events.EnvelopeMetadata) error {
			keyID := ""
			if event.Protection != nil {
				keyID = event.Protection.KeyID
			}
			if meta.ID != event.ID || meta.Type != event.Type || meta.Sequence != event.Sequence || meta.SchemaVersion != event.SchemaVersion || !meta.Time.Equal(event.Time) || meta.DeclaredKeyID != keyID {
				return ErrSource
			}
			found = true
			return nil
		}); err != nil {
			return err
		}
		if !found {
			return ErrSource
		}
		var lives []Lifetime
		if err := planner.Policy.replayLifetimesThrough(read, tenant.String(), head, func(life Lifetime) error { lives = append(lives, life); return nil }); err != nil {
			return err
		}
		for index, life := range lives {
			last := head
			if index+1 < len(lives) {
				last = lives[index+1].Registration.Sequence - 1
			}
			if event.Sequence < life.Registration.Sequence || event.Sequence > last {
				continue
			}
			if life.Activation == nil {
				return planner.Policy.withRegistrationFloor(read, life, planner.Custody, func(fenced context.Context, floor registrationFloor) error { return visit(fenced, floor.erased) })
			}
			if planner.Custody == nil {
				return ErrSource
			}
			ref := life.Activation.Body.Creation.Ref
			omitted := false
			err := planner.Custody.WithCustodyFence(read, ref, func(fenced context.Context) error {
				receipt, removed, err := planner.Custody.DestructionReceipt(fenced, ref)
				if err != nil {
					return err
				}
				if !removed {
					if life.Completion != nil {
						return eventprotect.ErrKey
					}
					return nil
				}
				claims, err := planner.Policy.verifyDestructionReceipt(receipt)
				if err != nil {
					return err
				}
				if !receiptMatchesAvailableLifetime(life, claims, head) || (life.Completion != nil && life.Completion.JWS != receipt) {
					return ErrSource
				}
				omitted = true
				return visit(fenced, true)
			})
			if err != nil || omitted {
				return err
			}
			// Live projection retains its ordinary lock order and may acquire custody
			// itself. Only the omission callback belongs inside this read-only fence.
			return visit(read, false)
		}
		return visit(read, false)
	})
}
