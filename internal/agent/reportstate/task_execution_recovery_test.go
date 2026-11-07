// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"context"
	"errors"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

type terminalObservationFixture struct {
	calls  int
	change func(*windependents.TaskTerminalObservation)
}

func (f *terminalObservationFixture) ObserveTerminalInstance(_ context.Context, task windependents.Task, instance string) (windependents.TaskTerminalObservation, bool, error) {
	f.calls++
	proof := taskFixtureProof(task)
	proof.InstanceID = instance
	proof.StartedAt = time.Now().UTC()
	proof.CompletedAt = proof.StartedAt
	proof.Actions[0].ResultCode = 1
	value := windependents.TaskTerminalObservation{Proof: proof, Quiescent: true, AllInstancesVisible: true, ObservedAt: time.Now().UTC()}
	if f.change != nil {
		f.change(&value)
	}
	return value, true, nil
}
func TestTaskRecoveryObservesTerminalButPreservesUnknownStartA267(t *testing.T) {
	root := t.TempDir()
	s, e := Open(root, "owned-task-recovery")
	if e != nil {
		t.Fatal(e)
	}
	task := taskFixtureSnapshot()
	runner := &retainedTaskFixture{unknown: true}
	if _, e = s.ExecuteTaskOnce(t.Context(), 731, "forward", task, runner); e == nil {
		t.Fatal("lost start falsely completed")
	}
	failed := Observation{JobID: 731, Attempt: 1, Outcome: "failed", Detail: []byte("native start reply unknown")}
	if e = s.Put(failed); e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(failed); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(root, "owned-task-recovery")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	fences, e := s.TaskExecutionFences(t.Context())
	if e != nil || len(fences) != 1 || fences[0].FencedAt.IsZero() {
		t.Fatal("exact recoverable fence missing", e)
	}
	observer := &terminalObservationFixture{}
	result, e := s.ReconcileTaskExecution(t.Context(), 731, "forward", taskFixtureProof(task).InstanceID, "owned-local-admin", "observe exact terminal instance before inverse", observer)
	if e != nil || !result.OriginalStartUnknown || result.Observation.Proof.Actions[0].ResultCode != 1 || runner.runs != 1 || observer.calls != 1 {
		t.Fatal("recovery repeated or reclassified original effect", e)
	}
	archived, found, e := s.readTaskExecutionArchive(731)
	if e != nil || !found || archived.Steps["forward"].Instance != "" || archived.Steps["forward"].Proof != nil || archived.Steps["forward"].Recovery == nil {
		t.Fatal("original uncertainty was rewritten instead of retaining a separate observation", e)
	}
	if _, e = s.ExecuteTaskOnce(t.Context(), 731, "forward", task, runner); !errors.Is(e, ErrTaskExecutionUncertain) || runner.runs != 1 {
		t.Fatal("resolved original was retried or became a success", e)
	}
	if _, e = s.ReconcileTaskExecution(t.Context(), 731, "forward", taskFixtureProof(task).InstanceID, "owned-local-admin", "observe exact terminal instance before inverse", observer); e != nil || observer.calls != 1 {
		t.Fatal("recovery retry replaced native observation", e)
	}
	if _, e = s.ReconcileTaskExecution(t.Context(), 731, "forward", taskFixtureProof(task).InstanceID, "owned-local-admin", "a different history", observer); e == nil {
		t.Fatal("later input rewrote retained recovery")
	}
	inverse := &retainedTaskFixture{}
	if _, e = s.ExecuteTaskOnce(t.Context(), 732, "inverse", task, inverse); e != nil || inverse.runs != 1 {
		t.Fatal("separate inverse remained blocked after exact terminal closure", e)
	}
}
func TestTaskRecoveryRefusesUnsafeAndLegacyObservationA267(t *testing.T) {
	for name, change := range map[string]func(*windependents.TaskTerminalObservation){"running": func(v *windependents.TaskTerminalObservation) { v.Quiescent = false }, "filtered visibility": func(v *windependents.TaskTerminalObservation) { v.AllInstancesVisible = false }, "historical": func(v *windependents.TaskTerminalObservation) { v.Proof.StartedAt = time.Unix(1700000000, 0) }, "foreign SID": func(v *windependents.TaskTerminalObservation) { v.Proof.AccountSID = "S-1-5-21-1-2-3-1002" }} {
		t.Run(name, func(t *testing.T) {
			s, e := Open(t.TempDir(), "unsafe-recovery")
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = s.Close() }()
			task := taskFixtureSnapshot()
			runner := &retainedTaskFixture{unknown: true}
			_, _ = s.ExecuteTaskOnce(t.Context(), 741, "forward", task, runner)
			if _, e = s.ReconcileTaskExecution(t.Context(), 741, "forward", taskFixtureProof(task).InstanceID, "admin", "owned reason", &terminalObservationFixture{change: change}); e == nil {
				t.Fatal("unsafe native evidence closed unknown start")
			}
			if _, e = s.ExecuteTaskOnce(t.Context(), 742, "inverse", task, runner); e == nil || runner.runs != 1 {
				t.Fatal("unsafe evidence enabled another run")
			}
		})
	}
	t.Run("legacy has no invented timestamp", func(t *testing.T) {
		s, e := Open(t.TempDir(), "legacy-recovery")
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = s.Close() }()
		task := taskFixtureSnapshot()
		p := &taskExecutionProjection{Steps: map[string]*taskExecutionState{}}
		if e = s.appendTaskExecution(p, taskExecutionEvent{Version: 1, JobID: 751, StepID: "forward", Phase: "fenced", Task: &task}); e != nil {
			t.Fatal(e)
		}
		observer := &terminalObservationFixture{}
		if _, e = s.ReconcileTaskExecution(t.Context(), 751, "forward", taskFixtureProof(task).InstanceID, "admin", "owned reason", observer); e == nil || observer.calls != 0 {
			t.Fatal("legacy unknown start gained invented timing authority")
		}
	})
}

func TestTaskRecoveryWaitsForOriginalReportAcknowledgementA267(t *testing.T) {
	s, e := Open(t.TempDir(), "owned-pending-recovery")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	task := taskFixtureSnapshot()
	runner := &retainedTaskFixture{unknown: true}
	_, _ = s.ExecuteTaskOnce(t.Context(), 781, "forward", task, runner)
	original := Observation{JobID: 781, Attempt: 1, Outcome: "failed", Detail: []byte("original unknown start")}
	if e = s.Put(original); e != nil {
		t.Fatal(e)
	}
	observer := &terminalObservationFixture{}
	if _, e = s.ReconcileTaskExecution(t.Context(), 781, "forward", taskFixtureProof(task).InstanceID, "admin", "owned observation before acknowledgement", observer); e != nil {
		t.Fatal(e)
	}
	fences, e := s.TaskExecutionFences(t.Context())
	if e != nil || len(fences) != 1 || fences[0].Recovery == nil {
		t.Fatal("unacknowledged source was discarded", e)
	}
	if e = s.TaskExecutionReady(t.Context(), task); e == nil {
		t.Fatal("new rotation bypassed unacknowledged original report")
	}
	if e = s.Acknowledge(original); e != nil {
		t.Fatal(e)
	}
	if e = s.TaskExecutionReady(t.Context(), task); e != nil {
		t.Fatal("acknowledged terminal observation did not free the active slot", e)
	}
	if _, e = s.ExecuteTaskOnce(t.Context(), 781, "forward", task, runner); !errors.Is(e, ErrTaskExecutionUncertain) || runner.runs != 1 {
		t.Fatal("acknowledgement reclassified or repeated original work", e)
	}
}

func TestTaskRecoveryKnownFailedInstanceStaysClosedA267(t *testing.T) {
	s, e := Open(t.TempDir(), "owned-known-terminal")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	task := taskFixtureSnapshot()
	runner := &retainedTaskFixture{lose: true}
	_, _ = s.ExecuteTaskOnce(t.Context(), 791, "forward", task, runner)
	observer := &terminalObservationFixture{}
	if _, e = s.ReconcileTaskExecution(t.Context(), 791, "forward", "b1234567-1234-1234-1234-123456789abc", "admin", "owned known instance", observer); e == nil || observer.calls != 0 {
		t.Fatal("known instance was substituted")
	}
	result, e := s.ReconcileTaskExecution(t.Context(), 791, "forward", taskFixtureProof(task).InstanceID, "admin", "owned known instance", observer)
	if e != nil || result.OriginalStartUnknown || result.Observation.Proof.Actions[0].ResultCode != 1 {
		t.Fatal("known failed native work lost exact history", e)
	}
	if _, e = s.ExecuteTaskOnce(t.Context(), 791, "forward", task, runner); !errors.Is(e, ErrTaskExecutionObservedTerminal) || runner.runs != 1 {
		t.Fatal("known failed terminal work was repeated or called success", e)
	}
}

func TestTaskRecoveryLegacyKnownInstanceStillObservesA267(t *testing.T) {
	root := t.TempDir()
	s, e := Open(root, "owned-legacy-known")
	if e != nil {
		t.Fatal(e)
	}
	task := taskFixtureSnapshot()
	p := &taskExecutionProjection{Steps: map[string]*taskExecutionState{}}
	if e = s.appendTaskExecution(p, taskExecutionEvent{Version: 1, JobID: 801, StepID: "forward", Phase: "fenced", Task: &task}); e != nil {
		t.Fatal(e)
	}
	if e = s.appendTaskExecution(p, taskExecutionEvent{Version: 1, JobID: 801, StepID: "forward", Phase: "started", Instance: taskFixtureProof(task).InstanceID}); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(root, "owned-legacy-known")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	fixture := &retainedTaskFixture{}
	if _, e = s.ExecuteTaskOnce(t.Context(), 801, "forward", task, fixture); e != nil || fixture.runs != 0 || fixture.observations != 1 {
		t.Fatal("legacy retained instance was rerun or lost", e)
	}
	retained, e := s.readTaskExecutions()
	if e != nil || retained.Steps["forward"].Version != 1 || !retained.Steps["forward"].FencedAt.IsZero() {
		t.Fatal("legacy source was rewritten with invented timing", e)
	}
}
