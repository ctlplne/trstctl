// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

type ErasurePlanCustody interface {
	WithCustodyFence(context.Context, eventprotect.KeyRef, func(context.Context) error) error
	DestructionReceipt(context.Context, eventprotect.KeyRef) (string, bool, error)
}

type ErasurePlanner struct {
	Policy  SourcePolicy
	Custody ErasurePlanCustody
}

type erasedLifetimeRange struct {
	tenant      string
	first, last uint64
	ref         eventprotect.KeyRef
	receipt     string
}

// ErasurePlan is produced from a complete finite source cut and current,
// independently fenced signed absence. Its private ranges do not grant removal.
// It does not assert that any pre-feature plaintext bytes became unreadable.
// Consumers supply events from this pinned source, never caller-made erased
// flags, and keep every omission inside WithSource during WithPlan.
type ErasurePlan struct {
	head    uint64
	ranges  []erasedLifetimeRange
	custody ErasurePlanCustody
	active  atomic.Bool
}

func (plan *ErasurePlan) Head() uint64 {
	if plan == nil {
		return 0
	}
	return plan.head
}

// WithSource verifies current absence again while making an omission. The
// callback runs under that tenant's independent custody fence. No caller flag,
// cached plan or SQL status authorizes skipping a retained event. Callers supply
// events read from this plan's pinned source and validate their schema even when
// omitted. The plan expires as soon as WithPlan returns.
func (plan *ErasurePlan) WithSource(ctx context.Context, event events.Event, visit func(context.Context, bool) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if plan == nil || !plan.active.Load() || visit == nil || event.Sequence == 0 || event.Sequence > plan.head {
		return ErrSource
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil {
		return visit(ctx, false)
	}
	for _, scope := range plan.ranges {
		if tenant.String() != scope.tenant || event.Sequence < scope.first || event.Sequence > scope.last {
			continue
		}
		return plan.custody.WithCustodyFence(ctx, scope.ref, func(fenced context.Context) error {
			receipt, erased, err := plan.custody.DestructionReceipt(fenced, scope.ref)
			if err != nil {
				return err
			}
			if !erased || receipt != scope.receipt {
				return eventprotect.ErrKey
			}
			return visit(fenced, true)
		})
	}
	return visit(ctx, false)
}

// WithPlan pins a complete finite source view. All lifetime and current receipt
// checks finish before the callback receives a plan. Omission uses WithSource to
// recheck absence under a single custody fence; locks do not accumulate across
// tenants. Missing material without completed signed evidence always refuses.
func (planner ErasurePlanner) WithPlan(ctx context.Context, visit func(context.Context, *ErasurePlan) error) error {
	if planner.Policy.Log == nil || visit == nil {
		return ErrSource
	}
	return planner.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		head, err := planner.Policy.Log.LastSequence(read)
		if err != nil {
			return err
		}
		tenants := map[string]bool{}
		// Activation controls are public, closed and independently parsed by
		// the complete lifetime fold below. Never open private registration,
		// offboard or credential bodies merely to discover protected tenants.
		types := []string{EventActivated}
		if planner.Custody != nil {
			types = append(types, eventRegistered)
		}
		if err := planner.Policy.Log.ReplayTypesThrough(read, 1, head, types, func(event events.Event) error {
			tenant, err := uuid.Parse(event.TenantID)
			if err != nil || tenant == uuid.Nil {
				return ErrSource
			}
			tenants[tenant.String()] = true
			return nil
		}); err != nil {
			return err
		}
		plan := &ErasurePlan{head: head, custody: planner.Custody}
		for tenant := range tenants {
			if planner.Custody == nil {
				return ErrSource
			}
			var lifetimes []Lifetime
			if err := planner.Policy.replayLifetimesThrough(read, tenant, head, func(life Lifetime) error { lifetimes = append(lifetimes, life); return nil }); err != nil {
				return err
			}
			for index, life := range lifetimes {
				if life.Activation == nil {
					if err := planner.Policy.withRegistrationFloor(read, life, planner.Custody, func(_ context.Context, floor registrationFloor) error {
						if floor.erased {
							last := head
							if index+1 < len(lifetimes) {
								last = lifetimes[index+1].Registration.Sequence - 1
							}
							plan.ranges = append(plan.ranges, erasedLifetimeRange{tenant: tenant, first: life.Registration.Sequence, last: last, ref: floor.ref, receipt: floor.receipt})
						}
						return nil
					}); err != nil {
						return err
					}
					continue
				}
				var erased bool
				var verifiedReceipt string
				ref := life.Activation.Body.Creation.Ref
				if err := planner.Custody.WithCustodyFence(read, ref, func(fenced context.Context) error {
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
					if !receiptMatchesAvailableLifetime(life, claims, head) {
						return ErrSource
					}
					if life.Completion != nil && life.Completion.JWS != receipt {
						return ErrSource
					}
					erased = true
					verifiedReceipt = receipt
					return nil
				}); err != nil {
					return err
				}
				if !erased {
					continue
				}
				last := head
				if index+1 < len(lifetimes) {
					last = lifetimes[index+1].Registration.Sequence - 1
				}
				plan.ranges = append(plan.ranges, erasedLifetimeRange{tenant: tenant, first: life.Registration.Sequence, last: last, ref: ref, receipt: verifiedReceipt})
			}
		}
		plan.active.Store(true)
		defer plan.active.Store(false)
		return visit(read, plan)
	})
}

// A cut older than the signed offboard may not contain it. Validate its exact
// activation, creation identity and original retention with signed coordinates,
// without appending an invented event or authorizing any destructive action.
func receiptMatchesAvailableLifetime(life Lifetime, claims eventprotect.DestructionClaims, head uint64) bool {
	if life.Activation == nil || claims.Request.Validate() != nil || claims.RemovedAt.Before(claims.Request.NotBefore) {
		return false
	}
	if life.Offboard != nil {
		return matchesLifetimeDestruction(life, claims.Request)
	}
	request := claims.Request
	if request.OffboardSequence <= head || !request.NotBefore.Equal(request.OffboardedAt.Add(time.Duration(life.Activation.Body.RetentionNanos))) {
		return false
	}
	// This temporary value is comparison material from the verified signature;
	// it is not retained source, does not escape, and grants no append/effect.
	expected := life
	expected.Offboard = &events.EnvelopeMetadata{ID: request.OffboardEventID, Type: eventOffboarded, TenantID: request.Ref.TenantID, Sequence: request.OffboardSequence, Time: request.OffboardedAt, SchemaVersion: 1}
	return matchesLifetimeDestruction(expected, request)
}
