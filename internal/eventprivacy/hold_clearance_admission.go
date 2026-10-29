// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

type HoldClearancePolicy interface {
	RequireClear(context.Context, Lifetime) error
	RequireOffboardClear(context.Context, Lifetime) error
}

func (admission SourceAdmission) holdClearanceDecision(ctx context.Context, event events.Event) (events.EventProtectionDecision, error) {
	clearance, err := parseHoldClearance(event, false)
	if err != nil {
		return events.EventProtectionDecision{}, ErrSource
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant.String() != clearance.Request.Ref.TenantID {
		return events.EventProtectionDecision{}, ErrSource
	}
	life, found, err := admission.Policy.LifetimeForKey(ctx, clearance.Request.Ref)
	if err != nil {
		return events.EventProtectionDecision{}, err
	}
	if !found || !matchesLifetimeDestruction(life, clearance.Request) {
		return events.EventProtectionDecision{}, ErrSource
	}
	if life.HoldClearance == nil {
		if admission.Holds == nil {
			return events.EventProtectionDecision{}, ErrSource
		}
		if err := admission.Holds.RequireClear(ctx, life); err != nil {
			return events.EventProtectionDecision{}, err
		}
	} else if life.HoldClearance.Meta.ID != event.ID {
		return events.EventProtectionDecision{}, ErrSource
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionPublicControl}, nil
}
