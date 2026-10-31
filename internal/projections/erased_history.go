// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

// WithEventProtectionErasurePlanner supplies current independently verified
// custody to read-model reconstruction. It grants no key creation or removal.
func WithEventProtectionErasurePlanner(planner *eventprivacy.ErasurePlanner) Option {
	return func(p *Projector) { p.eventProtectionErasurePlanner = planner }
}

type projectionErasureKey struct{}
type projectionErasureView struct {
	log  *events.Log
	plan *eventprivacy.ErasurePlan
}

func (p *Projector) withErasedHistory(ctx context.Context, log *events.Log, visit func(context.Context) error) error {
	if p.eventProtectionErasurePlanner == nil {
		return visit(ctx)
	}
	if view, ok := ctx.Value(projectionErasureKey{}).(projectionErasureView); ok {
		if view.log != log {
			return eventprivacy.ErrSource
		}
		return visit(ctx)
	}
	planner := *p.eventProtectionErasurePlanner
	if planner.Policy.Log != log {
		return eventprivacy.ErrSource
	}
	return planner.WithPlan(ctx, func(read context.Context, plan *eventprivacy.ErasurePlan) error {
		return visit(context.WithValue(read, projectionErasureKey{}, projectionErasureView{log: log, plan: plan}))
	})
}

func projectionHistoryHead(ctx context.Context, log *events.Log) (uint64, error) {
	if view, ok := ctx.Value(projectionErasureKey{}).(projectionErasureView); ok {
		if view.log != log {
			return 0, eventprivacy.ErrSource
		}
		return view.plan.Head(), nil
	}
	return log.LastSequence(ctx)
}

// Only derived projection callbacks use this adapter. Source policy, audit
// commitments, backup exports and operator source counts retain every record.
func projectionHistoryVisit(ctx context.Context, log *events.Log, visit func(events.Event) error) func(events.Event) error {
	return func(event events.Event) error {
		view, ok := ctx.Value(projectionErasureKey{}).(projectionErasureView)
		if !ok {
			return visit(event)
		}
		if view.log != log {
			return eventprivacy.ErrSource
		}
		return view.plan.WithSource(ctx, event, func(_ context.Context, omit bool) error {
			if omit {
				return ValidateSchemaVersion(event)
			}
			return visit(event)
		})
	}
}

func replayProjectionThrough(ctx context.Context, log *events.Log, from, through uint64, visit func(events.Event) error) error {
	if view, ok := ctx.Value(projectionErasureKey{}).(projectionErasureView); ok && through > view.plan.Head() {
		return eventprivacy.ErrSource
	}
	return log.ReplayThrough(ctx, from, through, projectionHistoryVisit(ctx, log, visit))
}
func replayProjectionTypesThrough(ctx context.Context, log *events.Log, from, through uint64, types []string, visit func(events.Event) error) error {
	if view, ok := ctx.Value(projectionErasureKey{}).(projectionErasureView); ok && through > view.plan.Head() {
		return eventprivacy.ErrSource
	}
	return log.ReplayTypesThrough(ctx, from, through, types, projectionHistoryVisit(ctx, log, visit))
}
func replayProjection(ctx context.Context, log *events.Log, from uint64, visit func(events.Event) error) error {
	head, err := projectionHistoryHead(ctx, log)
	if err != nil {
		return err
	}
	return replayProjectionThrough(ctx, log, from, head, visit)
}

func (p *Projector) rebuildWithPrivacyBarrier(ctx context.Context, log *events.Log) error {
	return p.withErasedHistory(ctx, log, func(read context.Context) error {
		if !p.allowSecretSyncRecoveryBootstrap {
			if err := p.validateSecretSyncRetainedHistory(read, log, false, false); err != nil {
				return err
			}
		}
		if err := p.rebuildFromPlannedHistory(read, log); err != nil {
			return err
		}
		return p.validateSecretSyncRetainedHistory(read, log, true, false)
	})
}
