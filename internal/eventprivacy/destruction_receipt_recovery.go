// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/events"
)

// verifiedCompletedReceipt publishes an already-completed effect. It never
// mints a removal grant or calls Destroy. An older restored source may lack the
// pre-removal clearance, but the exact signed receipt and CURRENT independent
// absence must both verify under the same custody fence and current SQL claim.
// This path requires the actual offboard in the available source cut; it does
// not invent an offboard for a backup that predates it.
func (receiver DestructionReceiver) verifiedCompletedReceipt(ctx context.Context, claim DestructionClaim, expected string) (events.Event, error) {
	var completion events.Event
	err := receiver.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		return receiver.Guard.WithTenantEventProtection(read, claim.Command.Ref.TenantID, func(guard context.Context) error {
			return receiver.Custody.WithCustodyFence(guard, claim.Command.Ref, func(fenced context.Context) error {
				return receiver.Claims.WithEventKeyDestructionClaim(fenced, claim, func(current context.Context) error {
					life, found, err := receiver.Policy.LifetimeForKey(current, claim.Command.Ref)
					if err != nil {
						return err
					}
					if !found || !matchesLifetimeDestruction(life, claim.Command) {
						return ErrSource
					}
					receipt, erased, err := receiver.Custody.DestructionReceipt(current, claim.Command.Ref)
					if err != nil {
						return err
					}
					if !erased || receipt != expected {
						return ErrSource
					}
					claims, err := receiver.Policy.verifyDestructionReceipt(receipt)
					if err != nil || !sameDestructionRequest(claims.Request, claim.Command) {
						return ErrSource
					}
					wire, err := json.Marshal(Destroyed{JWS: receipt})
					if err != nil {
						return err
					}
					at, id := claims.RemovedAt, DestructionEventID(claim.Command)
					if life.Completion != nil {
						if life.Completion.JWS != receipt {
							return ErrSource
						}
						at, id = life.Completion.Meta.Time, life.Completion.Meta.ID
					}
					completion = events.Event{ID: id, Type: EventDestroyed, TenantID: claim.Command.Ref.TenantID, SchemaVersion: 1, Time: at.UTC().Round(0), Data: wire}
					return nil
				})
			})
		})
	})
	return completion, err
}
