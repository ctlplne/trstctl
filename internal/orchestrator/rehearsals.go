// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/projections"
)

// Rehearsals of failure scenarios (A247): each change is one event.

// SaveRehearsalScenario records a scenario at a revision.
func (o *Orchestrator) SaveRehearsalScenario(ctx context.Context, tenantID string, saved projections.RehearsalScenarioSaved) error {
	return o.emitRehearsalEvent(ctx, tenantID, projections.EventRehearsalScenarioSaved, saved)
}

// StartRehearsalRun records what a run replays and against which versions.
func (o *Orchestrator) StartRehearsalRun(ctx context.Context, tenantID string, started projections.RehearsalRunStarted) error {
	return o.emitRehearsalEvent(ctx, tenantID, projections.EventRehearsalRunStarted, started)
}

// CompleteRehearsalRun records what a run observed, its verdict and label.
func (o *Orchestrator) CompleteRehearsalRun(ctx context.Context, tenantID string, completed projections.RehearsalRunCompleted) error {
	return o.emitRehearsalEvent(ctx, tenantID, projections.EventRehearsalRunCompleted, completed)
}

func (o *Orchestrator) emitRehearsalEvent(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, eventType, tenantID, data)
	return err
}
