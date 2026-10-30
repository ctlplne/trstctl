// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type DestructionClaim = store.EventKeyDestructionClaim

type DestructionClaims interface {
	WithEventKeyDestructionClaim(context.Context, DestructionClaim, func(context.Context) error) error
}

type DestructionCustody interface {
	WithCustodyFence(context.Context, eventprotect.KeyRef, func(context.Context) error) error
	Destroy(context.Context, eventprotect.DestructionRequest) (string, error)
	DestructionReceipt(context.Context, eventprotect.KeyRef) (string, bool, error)
}

type DestructionReceiver struct {
	Policy    SourcePolicy
	Claims    DestructionClaims
	Guard     TenantGuard
	Custody   DestructionCustody
	Authority *DestructionAuthority
	// Record preserves the exact public machine event and suppresses inherited
	// actor attribution. It runs outside history/custody callbacks, using the
	// assembled SQL/projection/backup order. It must verify the private current
	// claim grant; no event-type-only deleted-tenant bypass is permitted.
	Record func(context.Context, events.Event) (events.Event, error)
}

func DestructionEventID(request eventprotect.DestructionRequest) string {
	return request.OperationID + ":destroyed"
}

func (receiver DestructionReceiver) Destroy(ctx context.Context, claim DestructionClaim) error {
	if receiver.Policy.Log == nil || receiver.Claims == nil || receiver.Guard == nil || receiver.Custody == nil || receiver.Authority == nil || receiver.Record == nil || claim.Command.Validate() != nil {
		return ErrSource
	}
	return receiver.Claims.WithEventKeyDestructionClaim(ctx, claim, func(service context.Context) error {
		// Capture/validate complete retained hold state before removal. The
		// resulting closed fact survives the later loss of private hold bodies.
		var clearance events.Event
		err := receiver.Policy.Log.WithHistoryRead(service, func(read context.Context) error {
			return receiver.Guard.WithTenantEventProtection(read, claim.Command.Ref.TenantID, func(fenced context.Context) error {
				life, found, err := receiver.Policy.LifetimeForKey(fenced, claim.Command.Ref)
				if err != nil {
					return err
				}
				if !found || !matchesLifetimeDestruction(life, claim.Command) {
					return ErrSource
				}
				if life.HoldClearance != nil {
					return nil
				}
				wire, err := json.Marshal(HoldClearance{Request: claim.Command})
				if err != nil {
					return err
				}
				clearance = events.Event{ID: HoldClearanceEventID(claim.Command), Type: EventHoldClearance, TenantID: claim.Command.Ref.TenantID, SchemaVersion: 1, Data: wire}
				return nil
			})
		})
		if err != nil {
			return err
		}
		if clearance.ID != "" {
			// SourceAdmission independently validates the exact complete hold
			// cut under its append fence; merely building this body grants none.
			if err := receiver.recordControl(service, claim, clearance); err != nil {
				return err
			}
		}
		var completion events.Event
		err = receiver.Policy.Log.WithHistoryRead(service, func(read context.Context) error {
			return receiver.Guard.WithTenantEventProtection(read, claim.Command.Ref.TenantID, func(guard context.Context) error {
				return receiver.Custody.WithCustodyFence(guard, claim.Command.Ref, func(fenced context.Context) error {
					// Re-check SQL after waiting on independent custody. A source
					// event with a rolled-back or expired claim grants no effect.
					return receiver.Claims.WithEventKeyDestructionClaim(fenced, claim, func(current context.Context) error {
						life, found, err := receiver.Policy.LifetimeForKey(current, claim.Command.Ref)
						if err != nil {
							return err
						}
						if !found || !matchesLifetimeDestruction(life, claim.Command) || life.HoldClearance == nil || !sameDestructionRequest(life.HoldClearance.Body.Request, claim.Command) {
							return ErrSource
						}
						return receiver.Authority.withVerifiedDestructionGrant(current, claim.Command, func(granted context.Context) error {
							receipt, err := receiver.Custody.Destroy(granted, claim.Command)
							if err != nil {
								return err
							}
							claims, err := receiver.Policy.verifyDestructionReceipt(receipt)
							if err != nil || !sameDestructionRequest(claims.Request, claim.Command) {
								return ErrSource
							}
							actual, erased, err := receiver.Custody.DestructionReceipt(granted, claim.Command.Ref)
							if err != nil {
								return err
							}
							if !erased || actual != receipt {
								return eventprotect.ErrKey
							}
							wire, err := json.Marshal(Destroyed{JWS: receipt})
							if err != nil {
								return err
							}
							at := claims.RemovedAt
							if life.Completion != nil {
								if life.Completion.JWS != receipt {
									return ErrSource
								}
								at = life.Completion.Meta.Time
								completion = events.Event{ID: life.Completion.Meta.ID}
							} else {
								completion = events.Event{ID: DestructionEventID(claim.Command)}
							}
							completion.Type, completion.TenantID, completion.SchemaVersion, completion.Time, completion.Data = EventDestroyed, claim.Command.Ref.TenantID, 1, at.UTC().Round(0), wire
							return nil
						})
					})
				})
			})
		})
		if err != nil {
			return err
		}
		if completion.ID == "" || completion.Time.Equal(time.Time{}) {
			return ErrSource
		}
		return receiver.recordControl(service, claim, completion)
	})
}

func (receiver DestructionReceiver) recordControl(ctx context.Context, claim DestructionClaim, event events.Event) error {
	return receiver.Authority.withControlGrant(ctx, claim, event, func(granted context.Context) error {
		_, err := receiver.Record(events.ContextWithoutActor(granted), event)
		return err
	})
}
