// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"errors"
	"sort"
)

// nativeTaskEvent carries selected metadata only, never task arguments/XML.
type nativeTaskEvent struct {
	EventID                      uint32
	RecordID                     uint64
	Path, AccountSID, InstanceID string
	ResultCode                   uint32
	ResultPresent                bool
}

func taskProofFromEvents(task Task, instance string, events []nativeTaskEvent) (TaskRunProof, bool, error) {
	canonical, ok := canonicalTaskInstance(instance)
	if !ok || validateTask(task) != nil || len(events) > 128 {
		return TaskRunProof{}, false, errors.New("windows task: invalid bounded completion request")
	}
	proof := TaskRunProof{Path: task.Path, AccountSID: task.AccountSID, InstanceID: canonical}
	seen := map[uint64]bool{}
	for _, event := range events {
		observed, ok := canonicalTaskInstance(event.InstanceID)
		if !ok || observed != canonical || event.Path != task.Path || event.RecordID == 0 || seen[event.RecordID] {
			return TaskRunProof{}, false, errors.New("windows task: native completion event has foreign or duplicate authority")
		}
		seen[event.RecordID] = true
		switch event.EventID {
		case 100:
			if proof.StartRecordID != 0 || event.AccountSID != task.AccountSID {
				return TaskRunProof{}, false, errors.New("windows task: native start account or instance differs")
			}
			proof.StartRecordID = event.RecordID
		case 102:
			if proof.CompletionRecordID != 0 {
				return TaskRunProof{}, false, errors.New("windows task: duplicate native task completion")
			}
			proof.CompletionRecordID = event.RecordID
		case 201:
			if !event.ResultPresent || event.ResultCode != 0 {
				return TaskRunProof{}, false, errors.New("windows task: native action reported failure")
			}
			proof.Actions = append(proof.Actions, TaskActionResult{RecordID: event.RecordID, ResultCode: event.ResultCode})
			if len(proof.Actions) > int(task.ActionCount) {
				return TaskRunProof{}, false, errors.New("windows task: unexpected native action count")
			}
		default:
			return TaskRunProof{}, false, errors.New("windows task: unexpected completion event type")
		}
	}
	if proof.StartRecordID == 0 || proof.CompletionRecordID == 0 || len(proof.Actions) < int(task.ActionCount) {
		return TaskRunProof{}, false, nil
	}
	sort.Slice(proof.Actions, func(i, j int) bool { return proof.Actions[i].RecordID < proof.Actions[j].RecordID })
	if err := validateTaskRunProof(task, proof); err != nil {
		return TaskRunProof{}, false, err
	}
	return proof, true, nil
}
