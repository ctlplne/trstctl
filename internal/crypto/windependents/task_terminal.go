// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
	"sort"
	"time"
)

// TaskTerminalObservation licenses only closing a local execution fence. Failed
// action codes remain failures; this never licenses a successful work report.
type TaskTerminalObservation struct {
	Proof               TaskRunProof `json:"proof"`
	Quiescent           bool         `json:"quiescent"`
	AllInstancesVisible bool         `json:"all_instances_visible"`
	ObservedAt          time.Time    `json:"observed_at"`
}

func ValidateTaskTerminalProof(task Task, proof TaskRunProof) error {
	if validateTask(task) != nil {
		return errors.New("windows task: invalid terminal task authority")
	}
	if canonical, ok := canonicalTaskInstance(proof.InstanceID); !ok || canonical != proof.InstanceID || proof.Path != task.Path || proof.AccountSID != task.AccountSID || proof.StartRecordID == 0 || proof.CompletionRecordID <= proof.StartRecordID || len(proof.Actions) != int(task.ActionCount) || proof.StartedAt.IsZero() || proof.CompletedAt.IsZero() || proof.CompletedAt.Before(proof.StartedAt) {
		return errors.New("windows task: incomplete exact terminal observation")
	}
	seen := map[uint64]bool{}
	for _, action := range proof.Actions {
		if action.RecordID <= proof.StartRecordID || action.RecordID >= proof.CompletionRecordID || seen[action.RecordID] {
			return errors.New("windows task: terminal action record differs")
		}
		seen[action.RecordID] = true
	}
	return nil
}
func ValidateTaskTerminalObservation(task Task, instance string, observation TaskTerminalObservation) error {
	canonical, ok := canonicalTaskInstance(instance)
	if !ok || observation.Proof.InstanceID != canonical || !observation.Quiescent || !observation.AllInstancesVisible || observation.ObservedAt.IsZero() || observation.ObservedAt.Before(observation.Proof.CompletedAt) {
		return errors.New("windows task: exact instance completion and full quiescence are required")
	}
	return ValidateTaskTerminalProof(task, observation.Proof)
}

type terminalTaskInstanceObserver interface {
	observeTerminal(context.Context, Task, string) (TaskTerminalObservation, bool, error)
}

// ObserveTerminalInstance has no start/update/stop path. It requires exact native
// terminal records and an elevated view of every current instance of this task.
func (t *Tasks) ObserveTerminalInstance(ctx context.Context, task Task, instance string) (TaskTerminalObservation, bool, error) {
	canonical, ok := canonicalTaskInstance(instance)
	if !ok {
		return TaskTerminalObservation{}, false, errors.New("windows task: invalid terminal instance")
	}
	if err := t.inspectBound(ctx, task); err != nil {
		return TaskTerminalObservation{}, false, err
	}
	observer, ok := t.driver.(terminalTaskInstanceObserver)
	if !ok {
		return TaskTerminalObservation{}, false, errors.New("windows task: terminal observation is unavailable")
	}
	observation, ready, err := observer.observeTerminal(ctx, task, canonical)
	if err != nil || !ready {
		return TaskTerminalObservation{}, false, err
	}
	if err := ValidateTaskTerminalObservation(task, canonical, observation); err != nil {
		return TaskTerminalObservation{}, false, err
	}
	return observation, true, nil
}
func taskTerminalProofFromEvents(task Task, instance string, events []nativeTaskEvent) (TaskRunProof, bool, error) {
	canonical, ok := canonicalTaskInstance(instance)
	if !ok || validateTask(task) != nil || len(events) > 128 {
		return TaskRunProof{}, false, errors.New("windows task: invalid bounded terminal request")
	}
	proof := TaskRunProof{Path: task.Path, AccountSID: task.AccountSID, InstanceID: canonical}
	seen := map[uint64]bool{}
	for _, event := range events {
		observed, ok := canonicalTaskInstance(event.InstanceID)
		if !ok || observed != canonical || event.Path != task.Path || event.RecordID == 0 || seen[event.RecordID] {
			return TaskRunProof{}, false, errors.New("windows task: foreign or duplicate terminal event")
		}
		seen[event.RecordID] = true
		switch event.EventID {
		case 100:
			if proof.StartRecordID != 0 || event.AccountSID != task.AccountSID {
				return TaskRunProof{}, false, errors.New("windows task: terminal start identity differs")
			}
			proof.StartRecordID = event.RecordID
			proof.StartedAt = event.CreatedAt
		case 102:
			if proof.CompletionRecordID != 0 {
				return TaskRunProof{}, false, errors.New("windows task: duplicate terminal completion")
			}
			proof.CompletionRecordID = event.RecordID
			proof.CompletedAt = event.CreatedAt
		case 201:
			if !event.ResultPresent || len(proof.Actions) >= int(task.ActionCount) {
				return TaskRunProof{}, false, errors.New("windows task: terminal action result is missing or count differs")
			}
			proof.Actions = append(proof.Actions, TaskActionResult{RecordID: event.RecordID, ResultCode: event.ResultCode})
		default:
			return TaskRunProof{}, false, errors.New("windows task: unexpected terminal event")
		}
	}
	if proof.StartRecordID == 0 || proof.CompletionRecordID == 0 || len(proof.Actions) < int(task.ActionCount) {
		return TaskRunProof{}, false, nil
	}
	sort.Slice(proof.Actions, func(i, j int) bool { return proof.Actions[i].RecordID < proof.Actions[j].RecordID })
	if err := ValidateTaskTerminalProof(task, proof); err != nil {
		return TaskRunProof{}, false, err
	}
	return proof, true, nil
}
