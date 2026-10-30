// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"context"
	"sync/atomic"

	"trstctl.com/trstctl/internal/events"
)

type destructionControlGrantKey struct{}
type destructionControlGrant struct {
	authority *DestructionAuthority
	claim     DestructionClaim
	event     events.Event
	active    atomic.Bool
}

// ControlClaim checks a package-private short-lived grant for ONE complete
// public event. Production recording must independently revalidate this claim
// in SQL. This cannot authorize an arbitrary event just by matching its type.
func (authority *DestructionAuthority) ControlClaim(ctx context.Context, event events.Event) (DestructionClaim, error) {
	if err := ctx.Err(); err != nil {
		return DestructionClaim{}, err
	}
	grant, _ := ctx.Value(destructionControlGrantKey{}).(*destructionControlGrant)
	if authority == nil || grant == nil || grant.authority != authority || !grant.active.Load() || event.Actor != nil || event.Protection != nil || event.SensitiveErased {
		return DestructionClaim{}, ErrSource
	}
	expected := grant.event
	if event.Sequence != expected.Sequence || event.ID != expected.ID || event.TenantID != expected.TenantID || event.Type != expected.Type || event.SchemaVersion != expected.SchemaVersion || !event.Time.Equal(expected.Time) || !bytes.Equal(event.Data, expected.Data) {
		return DestructionClaim{}, ErrSource
	}
	return grant.claim, nil
}

func (authority *DestructionAuthority) withControlGrant(ctx context.Context, claim DestructionClaim, event events.Event, visit func(context.Context) error) error {
	if authority == nil || visit == nil || claim.Command.Validate() != nil || event.TenantID != claim.Command.Ref.TenantID || event.Actor != nil || event.Protection != nil || event.SensitiveErased {
		return ErrSource
	}
	if event.Type != EventHoldClearance && event.Type != EventDestroyed {
		return ErrSource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	grant := &destructionControlGrant{authority: authority, claim: claim, event: event}
	grant.event.Data = bytes.Clone(event.Data)
	grant.active.Store(true)
	defer grant.active.Store(false)
	return visit(context.WithValue(ctx, destructionControlGrantKey{}, grant))
}
