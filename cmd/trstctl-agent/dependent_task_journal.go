// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

func (r relayChannel) DependentTaskJournalReady(ctx context.Context, task windependents.Task) bool {
	return r.pending != nil && r.pending.TaskExecutionReady(ctx, task) == nil
}
func (r relayChannel) ExecuteDependentTaskOnce(ctx context.Context, jobID int64, stepID string, task windependents.Task, executor relay.DependentTaskExecutor) (windependents.TaskRunProof, error) {
	if r.pending == nil {
		return windependents.TaskRunProof{}, errors.New("agent: native task execution requires durable report state")
	}
	proof, e := r.pending.ExecuteTaskOnce(ctx, jobID, stepID, task, executor)
	if errors.Is(e, reportstate.ErrTaskExecutionUncertain) {
		return proof, errors.Join(relay.ErrDependentTaskUncertain, e)
	}
	return proof, e
}
