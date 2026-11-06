// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type ownedTaskDriver struct {
	current             Task
	proof               TaskRunProof
	writes, runs, reads int
}

func (d *ownedTaskDriver) discover(context.Context, string) ([]Task, error) {
	return []Task{d.current}, nil
}
func (d *ownedTaskDriver) inspect(context.Context, string) (Task, error) {
	d.reads++
	return d.current, nil
}
func (d *ownedTaskDriver) update(context.Context, Task, []byte) error { d.writes++; return nil }
func (d *ownedTaskDriver) run(context.Context, Task) (TaskRunProof, error) {
	d.runs++
	return d.proof, nil
}
func ownedTask() Task {
	return Task{Path: "\\owned\\work", AccountSID: "S-1-5-21-100-200-300-1001", ConfigSHA256: strings.Repeat("a", 64), Enabled: true, LogonType: 1, ActionCount: 1}
}
func ownedTaskProof() TaskRunProof {
	return TaskRunProof{Path: "\\owned\\work", AccountSID: "S-1-5-21-100-200-300-1001", InstanceID: "12345678-1234-4234-8234-123456789abc", StartRecordID: 10, CompletionRecordID: 13, Actions: []TaskActionResult{{RecordID: 12, ResultCode: 0}}}
}
func TestTaskNativeAuthorityAndFreshProofA267(t *testing.T) {
	target := ownedTask()
	driver := &ownedTaskDriver{current: target, proof: ownedTaskProof()}
	adapter, err := newTasks(driver, TaskExecutionPolicy{VerificationPaths: []string{target.Path}})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-task-password")); err != nil || driver.writes != 1 {
		t.Fatal("bound native task update failed")
	}
	if _, err := adapter.RunAndVerify(t.Context(), target); err != nil || driver.runs != 1 {
		t.Fatal("fresh native task evidence was not accepted")
	}
	for _, change := range []func(*Task){func(v *Task) { v.AccountSID = "S-1-5-21-100-200-300-1002" }, func(v *Task) { v.ConfigSHA256 = strings.Repeat("b", 64) }, func(v *Task) { v.Path = "\\different\\work" }, func(v *Task) { v.ActionCount = 2 }, func(v *Task) { v.Enabled = false }} {
		foreign := target
		change(&foreign)
		driver.current = foreign
		before := driver.writes
		if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-task-password")); err == nil || driver.writes != before {
			t.Fatal("changed task authority reached native mutation")
		}
	}
	driver.current = target
	for _, change := range []func(*TaskRunProof){func(v *TaskRunProof) { v.InstanceID = "" }, func(v *TaskRunProof) { v.StartRecordID = 0 }, func(v *TaskRunProof) { v.CompletionRecordID = 0 }, func(v *TaskRunProof) { v.AccountSID = "S-1-5-21-100-200-300-1002" }, func(v *TaskRunProof) { v.Path = "\\foreign\\work" }, func(v *TaskRunProof) { v.Actions = nil }, func(v *TaskRunProof) { v.Actions = []TaskActionResult{{RecordID: 9, ResultCode: 0}} }, func(v *TaskRunProof) { v.Actions = []TaskActionResult{{RecordID: 12, ResultCode: 1}} }} {
		driver.proof = ownedTaskProof()
		change(&driver.proof)
		if _, err := adapter.RunAndVerify(t.Context(), target); err == nil {
			t.Fatal("missing/foreign/failed per-instance completion was called success")
		}
	}
}
func TestTaskNativeNoUnreviewedExecutionA267(t *testing.T) {
	target := ownedTask()
	driver := &ownedTaskDriver{current: target, proof: ownedTaskProof()}
	adapter, err := newTasks(driver, TaskExecutionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.RunAndVerify(t.Context(), target); err == nil || driver.runs != 0 || driver.reads != 0 {
		t.Fatal("task ran without exact local verification authorization")
	}
	for _, path := range []string{"", "owned", "\\owned\\..\\work", "\\owned\\.\\work", "\\owned\\ work", "\\owned\\work ", "\\owned//work", "\\owned\\\\work"} {
		invalid := target
		invalid.Path = path
		if err := adapter.UpdatePassword(t.Context(), invalid, []byte("Tr5!owned-task-password")); err == nil {
			t.Fatal("invalid task path reached native mutation")
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := adapter.UpdatePassword(canceled, target, []byte("Tr5!owned-task-password")); err == nil || driver.writes != 0 {
		t.Fatal("canceled native task mutation admitted")
	}
}

func (d *ownedTaskDriver) observe(context.Context, Task, string) (TaskRunProof, bool, error) {
	return d.proof, true, nil
}
func TestTaskNativeObservationDoesNotRunAgainA267(t *testing.T) {
	target := ownedTask()
	driver := &ownedTaskDriver{current: target, proof: ownedTaskProof()}
	adapter, err := newTasks(driver, TaskExecutionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ready, err := adapter.ObserveInstance(t.Context(), target, driver.proof.InstanceID); err != nil || !ready || driver.runs != 0 {
		t.Fatal("read-only instance recovery started a new execution")
	}
	if _, ready, err := adapter.ObserveInstance(t.Context(), target, "12345678-1234-4234-8234-123456789abd"); err == nil || ready || driver.runs != 0 {
		t.Fatal("foreign instance observation admitted")
	}
}

func TestTaskNativeNonPasswordModesStayReadOnlyA267(t *testing.T) {
	for _, mode := range []uint32{2, 3, 4, 5, 6} {
		target := ownedTask()
		target.LogonType = mode
		driver := &ownedTaskDriver{current: target}
		adapter, err := newTasks(driver, TaskExecutionPolicy{VerificationPaths: []string{target.Path}})
		if err != nil {
			t.Fatal(err)
		}
		if found, err := adapter.Discover(t.Context(), target.AccountSID); err != nil || len(found) != 1 || found[0].LogonType != mode {
			t.Fatal("non-password principal was silently omitted from inventory")
		}
		if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-task-password")); err == nil || driver.writes != 0 {
			t.Fatal("unsupported logon mode reached credential update")
		}
		if _, err := adapter.RunAndVerify(t.Context(), target); err == nil || driver.runs != 0 {
			t.Fatal("unsupported logon mode reached task execution")
		}
	}
}

func TestTaskNativeMalformedProofIsNotRetryableA267(t *testing.T) {
	target := ownedTask()
	driver := &ownedTaskDriver{current: target, proof: ownedTaskProof()}
	driver.proof.Actions = nil
	adapter, err := newTasks(driver, TaskExecutionPolicy{VerificationPaths: []string{target.Path}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.RunAndVerify(t.Context(), target)
	var attempted *TaskExecutionError
	if !errors.As(err, &attempted) || driver.runs != 1 {
		t.Fatal("malformed post-execution proof was classified as a safe-to-repeat preflight failure")
	}
}
