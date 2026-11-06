// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/windependents"
)

type retainedTaskFixture struct {
	runs, observations int
	lose               bool
	unknown            bool
}

func taskFixtureSnapshot() windependents.Task {
	return windependents.Task{Path: "\\owned\\task", AccountSID: "S-1-5-21-1-2-3-1001", ConfigSHA256: strings.Repeat("a", 64), Enabled: true, LogonType: 1, ActionCount: 1}
}
func taskFixtureProof(task windependents.Task) windependents.TaskRunProof {
	return windependents.TaskRunProof{Path: task.Path, AccountSID: task.AccountSID, InstanceID: "a1234567-1234-1234-1234-123456789abc", StartRecordID: 10, CompletionRecordID: 12, Actions: []windependents.TaskActionResult{{RecordID: 11}}}
}
func (f *retainedTaskFixture) RunAndVerifyRetained(ctx context.Context, task windependents.Task, retain func(string) error) (windependents.TaskRunProof, error) {
	f.runs++
	proof := taskFixtureProof(task)
	if f.unknown {
		return windependents.TaskRunProof{}, &windependents.TaskExecutionError{Cause: errors.New("lost start reply")}
	}
	if err := retain(proof.InstanceID); err != nil {
		return windependents.TaskRunProof{}, err
	}
	if f.lose {
		return windependents.TaskRunProof{}, &windependents.TaskExecutionError{InstanceID: proof.InstanceID, Cause: errors.New("lost completion reply")}
	}
	return proof, nil
}
func (f *retainedTaskFixture) ObserveInstance(ctx context.Context, task windependents.Task, instance string) (windependents.TaskRunProof, bool, error) {
	f.observations++
	proof := taskFixtureProof(task)
	if instance != proof.InstanceID {
		return windependents.TaskRunProof{}, false, errors.New("wrong instance")
	}
	return proof, true, nil
}
func TestTaskExecutionOnceAcrossRestartA267(t *testing.T) {
	root := t.TempDir()
	task := taskFixtureSnapshot()
	fixture := &retainedTaskFixture{lose: true}
	store, err := Open(root, "tenant/agent/server")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 71, "forward-task", task, fixture); err == nil {
		t.Fatal("lost result claimed complete")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(root, "tenant/agent/server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	proof, err := store.ExecuteTaskOnce(t.Context(), 71, "forward-task", task, fixture)
	if err != nil || proof.InstanceID != taskFixtureProof(task).InstanceID || fixture.runs != 1 || fixture.observations != 1 {
		t.Fatal("retry repeated task instead of observing retained instance", err)
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 71, "forward-task", task, fixture); err != nil || fixture.runs != 1 || fixture.observations != 1 {
		t.Fatal("completed result not retained")
	}
	altered := task
	altered.ConfigSHA256 = strings.Repeat("b", 64)
	if _, err = store.ExecuteTaskOnce(t.Context(), 71, "forward-task", altered, fixture); err == nil {
		t.Fatal("changed task authority reused journal")
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 72, "forward-task", task, fixture); err == nil {
		t.Fatal("different job replaced unfinished journal")
	}
	raw, err := openReportTestRoot(t, root).ReadFile("task-executions.events")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), task.Path) || strings.Contains(string(raw), task.AccountSID) {
		t.Fatal("public host inventory escaped sealed journal")
	}
}
func TestTaskExecutionUnknownStartNeverRepeatsA267(t *testing.T) {
	root := t.TempDir()
	fixture := &retainedTaskFixture{unknown: true}
	task := taskFixtureSnapshot()
	store, err := Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 81, "task", task, fixture); err == nil {
		t.Fatal("unknown start claimed complete")
	}
	_ = store.Close()
	store, err = Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err = store.ExecuteTaskOnce(t.Context(), 81, "task", task, fixture); !errors.Is(err, ErrTaskExecutionUncertain) {
		t.Fatal("unknown start did not preserve uncertainty", err)
	}
	if fixture.runs != 1 || fixture.observations != 0 {
		t.Fatal("unknown native start was repeated or guessed")
	}
}
func TestTaskExecutionJournalRejectsCorruptionAndMissingKeyA267(t *testing.T) {
	for _, kind := range []string{"tail", "key", "binding"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			fixture := &retainedTaskFixture{unknown: true}
			store, err := Open(root, "bound")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = store.ExecuteTaskOnce(t.Context(), 91, "task", taskFixtureSnapshot(), fixture)
			_ = store.Close()
			binding := "bound"
			switch kind {
			case "tail":
				f, err := openReportTestRoot(t, root).OpenFile("task-executions.events", os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte{0, 0})
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "key":
				if err := os.Remove(filepath.Join(root, "sealing.key")); err != nil {
					t.Fatal(err)
				}
			case "binding":
				binding = "different"
			}
			reopened, err := Open(root, binding)
			if err == nil {
				_ = reopened.Close()
				t.Fatal("damaged/unbound journal admitted")
			}
			if _, err := os.Stat(filepath.Join(root, "task-executions.events")); err != nil {
				t.Fatal("refused journal was removed")
			}
			if kind == "key" {
				if _, err := os.Stat(filepath.Join(root, "sealing.key")); !os.IsNotExist(err) {
					t.Fatal("missing sealing key replaced")
				}
			}
		})
	}
}

func TestTaskExecutionFailedReportKeepsUnknownFenceA267(t *testing.T) {
	root := t.TempDir()
	fixture := &retainedTaskFixture{unknown: true}
	task := taskFixtureSnapshot()
	store, err := Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 101, "task", task, fixture); err == nil {
		t.Fatal("unknown start claimed complete")
	}
	report := Observation{JobID: 101, Attempt: 1, Outcome: "failed", Detail: []byte("native instance reply was lost")}
	if err = store.Put(report); err != nil {
		t.Fatal(err)
	}
	if err = store.Acknowledge(report); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	store, err = Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err = store.ExecuteTaskOnce(t.Context(), 101, "task", task, fixture); !errors.Is(err, ErrTaskExecutionUncertain) {
		t.Fatal("failed-report acknowledgement discarded unknown start fence", err)
	}
	if fixture.runs != 1 {
		t.Fatal("failed job retry duplicated the native task")
	}
}
func TestTaskExecutionCompletedReportRetiresOnlyExactJournalA267(t *testing.T) {
	root := t.TempDir()
	fixture := &retainedTaskFixture{}
	task := taskFixtureSnapshot()
	store, err := Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err = store.ExecuteTaskOnce(t.Context(), 111, "task", task, fixture); err != nil {
		t.Fatal(err)
	}
	report := Observation{JobID: 111, Attempt: 2, Outcome: "verified"}
	if err = store.Put(report); err != nil {
		t.Fatal(err)
	}
	altered := report
	altered.JobID = 112
	if err = store.Acknowledge(altered); err == nil {
		t.Fatal("different job acknowledgement accepted")
	}
	if err = store.Acknowledge(report); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, taskExecutionFile)); !os.IsNotExist(err) {
		t.Fatal("completed acknowledged execution journal retained")
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 112, "task", task, fixture); err != nil {
		t.Fatal("next acknowledged job blocked", err)
	}
}

func TestTaskExecutionFailedFunctionalReportPreservesCompletedInstanceA267(t *testing.T) {
	root := t.TempDir()
	task := taskFixtureSnapshot()
	fixture := &retainedTaskFixture{}
	store, err := Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ExecuteTaskOnce(t.Context(), 121, "task", task, fixture); err != nil {
		t.Fatal(err)
	}
	report := Observation{JobID: 121, Attempt: 1, Outcome: "failed", Detail: []byte("independent functional probe failed")}
	if err = store.Put(report); err != nil {
		t.Fatal(err)
	}
	if err = store.Acknowledge(report); err != nil {
		t.Fatal(err)
	}
	unrelated := Observation{JobID: 122, Attempt: 1, Outcome: "verified"}
	if err = store.Put(unrelated); err != nil {
		t.Fatal(err)
	}
	if err = store.Acknowledge(unrelated); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	store, err = Open(root, "bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err = store.ExecuteTaskOnce(t.Context(), 121, "task", task, fixture); err != nil || fixture.runs != 1 {
		t.Fatal("functional retry or unrelated report repeated the native task", err)
	}
}
func TestTaskExecutionUnresolvedCannotReportSuccessA267(t *testing.T) {
	store, err := Open(t.TempDir(), "bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	_, _ = store.ExecuteTaskOnce(t.Context(), 131, "task", taskFixtureSnapshot(), &retainedTaskFixture{unknown: true})
	if err = store.Put(Observation{JobID: 131, Attempt: 1, Outcome: "verified"}); err == nil {
		t.Fatal("unresolved start reported complete")
	}
}
func FuzzTaskExecutionEventProjectionA267(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("{\"version\":1,\"job_id\":1,\"step_id\":\"task\",\"phase\":\"started\",\"instance\":\"a1234567-1234-1234-1234-123456789abc\"}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxTaskExecutionFrame {
			return
		}
		var event taskExecutionEvent
		if json.Unmarshal(raw, &event) != nil {
			return
		}
		p := &taskExecutionProjection{Steps: map[string]*taskExecutionState{}}
		if err := p.apply(event); err == nil {
			if p.JobID <= 0 || p.Sequence != 1 || len(p.Steps) != 1 || event.Phase != "fenced" {
				t.Fatal("unbound event became a valid source state")
			}
			if err := p.apply(event); err == nil {
				t.Fatal("duplicate source event admitted")
			}
		}
	})
}

type crashBeforeInstanceFixture struct {
	retainedTaskFixture
	root string
}

func (f *crashBeforeInstanceFixture) RunAndVerifyRetained(ctx context.Context, task windependents.Task, retain func(string) error) (windependents.TaskRunProof, error) {
	// This independent effect receipt must survive the abrupt process exit.
	file, err := os.OpenFile(filepath.Join(f.root, "effect.receipt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return windependents.TaskRunProof{}, err
	}
	if _, err = file.Write([]byte("one start")); err != nil {
		return windependents.TaskRunProof{}, err
	}
	if err = file.Sync(); err != nil {
		return windependents.TaskRunProof{}, err
	}
	if err = file.Close(); err != nil {
		return windependents.TaskRunProof{}, err
	}
	os.Exit(89)
	return windependents.TaskRunProof{}, errors.New("unreachable crash fixture")
}
func TestTaskExecutionCrashChildA267(t *testing.T) {
	root := os.Getenv("TRSTCTL_A267_JOURNAL_CRASH_ROOT")
	if root == "" {
		t.Skip("isolated crash subprocess only")
	}
	store, err := Open(root, "crash-bound")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ExecuteTaskOnce(t.Context(), 141, "task", taskFixtureSnapshot(), &crashBeforeInstanceFixture{root: root})
	t.Fatal("child did not exit after one effect", err)
}
func TestTaskExecutionAbruptProcessExitDoesNotRepeatA267(t *testing.T) {
	root := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "-test.run=^TestTaskExecutionCrashChildA267$") // #nosec G204 -- the current Go test executable and one fixed test name, public owned fixture root only, no shell or credential (CWE-78)
	command.Env = append(os.Environ(), "TRSTCTL_A267_JOURNAL_CRASH_ROOT="+root)
	err = command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 89 {
		t.Fatal("owned child did not reach the injected abrupt exit", err)
	}
	receipt, err := openReportTestRoot(t, root).ReadFile("effect.receipt")
	if err != nil || string(receipt) != "one start" {
		t.Fatal("independent effect receipt missing", err)
	}
	store, err := Open(root, "crash-bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	fixture := &retainedTaskFixture{}
	if _, err = store.ExecuteTaskOnce(t.Context(), 141, "task", taskFixtureSnapshot(), fixture); !errors.Is(err, ErrTaskExecutionUncertain) || fixture.runs != 0 || fixture.observations != 0 {
		t.Fatal("abrupt exit lost the durable start fence", err)
	}
}

type distinctTaskExecutionFixture struct{ runs int }

func (f *distinctTaskExecutionFixture) RunAndVerifyRetained(_ context.Context, task windependents.Task, retain func(string) error) (windependents.TaskRunProof, error) {
	f.runs++
	proof := taskFixtureProof(task)
	if f.runs == 1 {
		proof.InstanceID = "a1234567-1234-1234-1234-123456789001"
	} else {
		proof.InstanceID = "a1234567-1234-1234-1234-123456789002"
	}
	if e := retain(proof.InstanceID); e != nil {
		return windependents.TaskRunProof{}, e
	}
	return proof, nil
}
func (f *distinctTaskExecutionFixture) ObserveInstance(_ context.Context, task windependents.Task, instance string) (windependents.TaskRunProof, bool, error) {
	proof := taskFixtureProof(task)
	proof.InstanceID = instance
	return proof, true, nil
}
func TestTaskExecutionKnownFailedWorkAllowsInverseWithoutReplayingOriginalA267(t *testing.T) {
	root := t.TempDir()
	task := taskFixtureSnapshot()
	fixture := &distinctTaskExecutionFixture{}
	s, e := Open(root, "known-forward-and-inverse")
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.ExecuteTaskOnce(t.Context(), 701, "forward", task, fixture)
	if e != nil {
		t.Fatal(e)
	}
	failed := Observation{JobID: 701, Attempt: 1, Outcome: "failed", Detail: []byte("independent functional probe failed")}
	if e = s.Put(failed); e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(failed); e != nil {
		t.Fatal(e)
	}
	inverse, e := s.ExecuteTaskOnce(t.Context(), 702, "inverse", task, fixture)
	if e != nil || fixture.runs != 2 || inverse.InstanceID == first.InstanceID {
		t.Fatal("known completed failed work blocked a distinct approved inverse", e)
	}
	done := Observation{JobID: 702, Attempt: 1, Outcome: "verified"}
	if e = s.Put(done); e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(done); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(root, "known-forward-and-inverse")
	if e != nil {
		t.Fatal(e)
	}
	old, e := s.ExecuteTaskOnce(t.Context(), 701, "forward", task, fixture)
	if e != nil || fixture.runs != 2 || old.InstanceID != first.InstanceID {
		t.Fatal("inverse erased the original failed-work fence or repeated its effect", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = openReportTestRoot(t, root).Remove("sealing.key"); e != nil {
		t.Fatal(e)
	}
	if other, e := Open(root, "known-forward-and-inverse"); e == nil {
		_ = other.Close()
		t.Fatal("archived native fences allowed a replacement sealing key")
	}
}
func TestTaskExecutionUnknownFailedWorkStillBlocksInverseA267(t *testing.T) {
	s, e := Open(t.TempDir(), "unknown-forward-and-inverse")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	fixture := &retainedTaskFixture{unknown: true}
	task := taskFixtureSnapshot()
	if _, e = s.ExecuteTaskOnce(t.Context(), 711, "forward", task, fixture); e == nil {
		t.Fatal("unknown start claimed complete")
	}
	failed := Observation{JobID: 711, Attempt: 1, Outcome: "failed", Detail: []byte("native start response was lost")}
	if e = s.Put(failed); e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(failed); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ExecuteTaskOnce(t.Context(), 712, "inverse", task, fixture); e == nil || fixture.runs != 1 {
		t.Fatal("unknown native start was blindly repeated as inverse work")
	}
}

func TestTaskExecutionCompletedArchiveRecoversBetweenLinkAndRemovalA267(t *testing.T) {
	root := t.TempDir()
	task := taskFixtureSnapshot()
	fixture := &distinctTaskExecutionFixture{}
	s, e := Open(root, "archive-interruption")
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.ExecuteTaskOnce(t.Context(), 721, "forward", task, fixture)
	if e != nil {
		t.Fatal(e)
	}
	failed := Observation{JobID: 721, Attempt: 1, Outcome: "failed", Detail: []byte("functional verification is unavailable")}
	if e = s.Put(failed); e != nil {
		t.Fatal(e)
	}
	// Exact fault point: the durable archive name exists, while the original
	// active name and pending failed acknowledgement have not been removed.
	if e = s.root.Link(taskExecutionFile, taskExecutionArchiveName(721)); e != nil {
		t.Fatal(e)
	}
	if e = syncDirectory(s.root); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(root, "archive-interruption")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	if e = s.TaskExecutionReady(t.Context(), task); e == nil {
		t.Fatal("unacknowledged work passed native preflight")
	}
	if e = s.Acknowledge(failed); e != nil {
		t.Fatal("interrupted archive acknowledgement did not resume", e)
	}
	if e = s.TaskExecutionReady(t.Context(), task); e != nil {
		t.Fatal("known completed work remained globally active", e)
	}
	if _, e = s.ExecuteTaskOnce(t.Context(), 722, "inverse", task, fixture); e != nil || fixture.runs != 2 {
		t.Fatal("inverse did not run after exact failed acknowledgement", e)
	}
	retained, e := s.ExecuteTaskOnce(t.Context(), 721, "forward", task, fixture)
	if e != nil || retained.InstanceID != first.InstanceID || fixture.runs != 2 {
		t.Fatal("interrupted archival lost the original fence", e)
	}
}
