// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"unicode/utf8"
)

var ErrTaskExecutionObservedTerminal = errors.New("reportstate: task history has a separate terminal observation; original execution cannot run again")

// TerminalTaskObserver deliberately has no Run, update, stop or credential API.
type TerminalTaskObserver interface {
	ObserveTerminalInstance(context.Context, windependents.Task, string) (windependents.TaskTerminalObservation, bool, error)
}
type TaskExecutionRecovery struct {
	Observation          windependents.TaskTerminalObservation `json:"observation"`
	Actor                string                                `json:"actor"`
	Reason               string                                `json:"reason"`
	At                   time.Time                             `json:"at"`
	OriginalStartUnknown bool                                  `json:"original_start_unknown"`
}
type TaskExecutionFence struct {
	JobID       int64                       `json:"job_id"`
	StepID      string                      `json:"step_id"`
	Task        windependents.Task          `json:"task"`
	Version     int                         `json:"version"`
	FencedAt    time.Time                   `json:"fenced_at,omitempty"`
	Instance    string                      `json:"instance,omitempty"`
	Recovery    *TaskExecutionRecovery      `json:"recovery,omitempty"`
	NativeProof *windependents.TaskRunProof `json:"native_proof,omitempty"`
}

func validTaskRecoveryInput(jobID int64, stepID, instance, actor, reason string) bool {
	canonical, ok := windependents.CanonicalTaskInstance(instance)
	return jobID > 0 && taskStepValid(stepID) && ok && canonical == instance && strings.TrimSpace(actor) == actor && len(actor) > 0 && len(actor) <= 512 && utf8.ValidString(actor) && strings.TrimSpace(reason) == reason && len(reason) > 0 && len(reason) <= 4096 && utf8.ValidString(reason)
}
func validateTaskRecovery(state taskExecutionState, recovery TaskExecutionRecovery) error {
	instance := recovery.Observation.Proof.InstanceID
	if state.Version != 2 || state.FencedAt.IsZero() || state.Proof != nil || !validTaskRecoveryInput(1, "observed", instance, recovery.Actor, recovery.Reason) || recovery.OriginalStartUnknown != (state.Instance == "") || state.Instance != "" && state.Instance != instance || recovery.At.IsZero() || recovery.At.Before(recovery.Observation.ObservedAt) || recovery.Observation.Proof.StartedAt.Before(state.FencedAt) {
		return errors.New("reportstate: terminal recovery does not bind the exact timestamped execution fence")
	}
	return windependents.ValidateTaskTerminalObservation(state.Task, instance, recovery.Observation)
}
func (s *Store) TaskExecutionFences(ctx context.Context) ([]TaskExecutionFence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fs.ErrClosed
	}
	if s.fault != nil {
		return nil, s.fault
	}
	p, err := s.readTaskExecutions()
	if err != nil {
		return nil, err
	}
	result := make([]TaskExecutionFence, 0, len(p.Steps))
	for id, state := range p.Steps {
		result = append(result, TaskExecutionFence{JobID: p.JobID, StepID: id, Task: state.Task, Version: state.Version, FencedAt: state.FencedAt, Instance: state.Instance, Recovery: state.Recovery, NativeProof: state.Proof})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StepID < result[j].StepID })
	return result, nil
}
func matchingTaskRecovery(recovery *TaskExecutionRecovery, instance, actor, reason string) bool {
	return recovery != nil && recovery.Observation.Proof.InstanceID == instance && recovery.Actor == actor && recovery.Reason == reason
}
func (s *Store) taskRecoveryState(jobID int64, stepID string) (*taskExecutionProjection, *taskExecutionState, bool, error) {
	if s.closed {
		return nil, nil, false, fs.ErrClosed
	}
	if s.fault != nil {
		return nil, nil, false, s.fault
	}
	p, err := s.readTaskExecutions()
	if err != nil {
		return nil, nil, false, err
	}
	if p.JobID == jobID {
		if state := p.Steps[stepID]; state != nil {
			return p, state, false, nil
		}
	}
	archived, found, err := s.readTaskExecutionArchive(jobID)
	if err != nil {
		return nil, nil, false, err
	}
	if found {
		if state := archived.Steps[stepID]; state != nil {
			return archived, state, true, nil
		}
	}
	return nil, nil, false, errors.New("reportstate: exact retained task execution was not found")
}
func (s *Store) archiveRecoveredTaskWhenReady(p *taskExecutionProjection) error {
	if !completedTaskExecution(p) {
		return nil
	}
	pending, err := s.read()
	if err != nil {
		return err
	}
	if pending != nil {
		pending.Destroy()
		return nil
	}
	return s.archiveCompletedTaskExecution(p)
}

// ReconcileTaskExecution appends a separate terminal observation. The original
// unknown start stays unknown, cannot become a successful report, and cannot run
// again. Only independently authorized later work can use the freed active slot.
func (s *Store) ReconcileTaskExecution(ctx context.Context, jobID int64, stepID, instance, actor, reason string, observer TerminalTaskObserver) (TaskExecutionRecovery, error) {
	if s == nil || observer == nil || !validTaskRecoveryInput(jobID, stepID, instance, actor, reason) {
		return TaskExecutionRecovery{}, errors.New("reportstate: exact job, step, native instance, local actor and bounded reason required")
	}
	if err := ctx.Err(); err != nil {
		return TaskExecutionRecovery{}, err
	}
	if !s.taskMu.TryLock() {
		return TaskExecutionRecovery{}, errors.New("reportstate: task observation worker is busy")
	}
	defer s.taskMu.Unlock()
	s.mu.Lock()
	p, state, archived, err := s.taskRecoveryState(jobID, stepID)
	if err != nil {
		s.mu.Unlock()
		return TaskExecutionRecovery{}, err
	}
	if state.Recovery != nil {
		result := *state.Recovery
		if !matchingTaskRecovery(state.Recovery, instance, actor, reason) {
			s.mu.Unlock()
			return TaskExecutionRecovery{}, errors.New("reportstate: first terminal recovery observation differs")
		}
		if !archived {
			err = s.archiveRecoveredTaskWhenReady(p)
		}
		s.mu.Unlock()
		return result, err
	}
	if archived || state.Version != 2 || state.FencedAt.IsZero() || state.Proof != nil || state.Instance != "" && state.Instance != instance {
		s.mu.Unlock()
		return TaskExecutionRecovery{}, errors.New("reportstate: exact unresolved timestamped native task fence required")
	}
	original := *state
	s.mu.Unlock()
	observation, ready, err := observer.ObserveTerminalInstance(ctx, original.Task, instance)
	if err != nil {
		return TaskExecutionRecovery{}, err
	}
	if !ready {
		return TaskExecutionRecovery{}, errors.New("reportstate: exact native instance is not terminal")
	}
	result := TaskExecutionRecovery{Observation: observation, Actor: actor, Reason: reason, At: time.Now().UTC(), OriginalStartUnknown: original.Instance == ""}
	if err := validateTaskRecovery(original, result); err != nil {
		return TaskExecutionRecovery{}, err
	}
	if err := ctx.Err(); err != nil {
		return TaskExecutionRecovery{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, state, archived, err = s.taskRecoveryState(jobID, stepID)
	if err != nil {
		return TaskExecutionRecovery{}, err
	}
	if archived || state.Version != original.Version || !state.FencedAt.Equal(original.FencedAt) || state.Task != original.Task || state.Instance != original.Instance || state.Proof != nil || state.Recovery != nil {
		return TaskExecutionRecovery{}, errors.New("reportstate: execution authority changed during terminal observation")
	}
	if err := s.appendTaskExecution(p, taskExecutionEvent{Version: 2, JobID: jobID, StepID: stepID, Phase: "observed_terminal", At: result.At, Recovery: &result}); err != nil {
		return TaskExecutionRecovery{}, err
	}
	if err := s.archiveRecoveredTaskWhenReady(p); err != nil {
		return result, err
	}
	return result, nil
}

// OpenExisting takes the process lock but never creates a directory or sealing
// key. Operator inspection/recovery must not manufacture replacement state.
func OpenExisting(path, binding string) (*Store, error) {
	s, err := lockStoreMode(path, binding, false)
	if err != nil {
		return nil, err
	}
	if err := s.loadWithKeyCreation(false); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}
