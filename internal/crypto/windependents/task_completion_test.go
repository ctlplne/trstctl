// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"testing"
	"testing/quick"
	"time"
)

func ownedTaskEvents() []nativeTaskEvent {
	task := ownedTask()
	instance := ownedTaskProof().InstanceID
	return []nativeTaskEvent{{EventID: 100, RecordID: 10, Path: task.Path, AccountSID: task.AccountSID, InstanceID: instance}, {EventID: 201, RecordID: 12, Path: task.Path, InstanceID: instance, ResultPresent: true}, {EventID: 102, RecordID: 13, Path: task.Path, InstanceID: instance}}
}
func TestTaskCompletionNeedsNativeInstanceEventsA267(t *testing.T) {
	task := ownedTask()
	instance := ownedTaskProof().InstanceID
	proof, ready, err := taskProofFromEvents(task, instance, ownedTaskEvents())
	if err != nil || !ready || validateTaskRunProof(task, proof) != nil {
		t.Fatal("complete native instance proof rejected")
	}
	for _, events := range [][]nativeTaskEvent{nil, ownedTaskEvents()[:1], ownedTaskEvents()[:2]} {
		if _, ready, err := taskProofFromEvents(task, instance, events); err != nil || ready {
			t.Fatal("partial native events were claimed complete")
		}
	}
	for _, mutate := range []func([]nativeTaskEvent){func(v []nativeTaskEvent) { v[0].AccountSID = "S-1-5-21-100-200-300-1002" }, func(v []nativeTaskEvent) { v[1].ResultPresent = false }, func(v []nativeTaskEvent) { v[1].ResultCode = 1 }, func(v []nativeTaskEvent) { v[2].RecordID = 9 }, func(v []nativeTaskEvent) { v[1].RecordID = v[0].RecordID }, func(v []nativeTaskEvent) { v[2].Path = "\\foreign\\task" }, func(v []nativeTaskEvent) { v[0].InstanceID = "12345678-1234-4234-8234-123456789abd" }} {
		events := ownedTaskEvents()
		mutate(events)
		if _, ready, err := taskProofFromEvents(task, instance, events); err == nil || ready {
			t.Fatal("missing/failed/foreign native evidence admitted")
		}
	}
	if err := quick.Check(func(a, b, c uint8) bool {
		events := ownedTaskEvents()
		indices := []uint8{a % 3, b % 3, c % 3}
		if indices[0] == indices[1] || indices[0] == indices[2] || indices[1] == indices[2] {
			return true
		}
		reordered := []nativeTaskEvent{events[indices[0]], events[indices[1]], events[indices[2]]}
		_, ready, err := taskProofFromEvents(task, instance, reordered)
		return ready && err == nil
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeTaskCompletionRetainsEventTimesA267(t *testing.T) {
	events := ownedTaskEvents()
	start := time.Unix(1700000000, 0).UTC()
	for i := range events {
		events[i].CreatedAt = start.Add(time.Duration(i) * time.Second)
	}
	task := ownedTask()
	instance := ownedTaskProof().InstanceID
	proof, ready, e := taskProofFromEvents(task, instance, events)
	if e != nil || !ready || !proof.StartedAt.Equal(events[0].CreatedAt) || !proof.CompletedAt.Equal(events[2].CreatedAt) {
		t.Fatal("native task event times were lost")
	}
	if e = ValidateTaskRunFreshness(task, proof, start, start.Add(time.Minute)); e != nil {
		t.Fatal("fresh native task instance refused", e)
	}
	if e = ValidateTaskRunFreshness(task, proof, start.Add(time.Second), start.Add(time.Minute)); e == nil {
		t.Fatal("historical native task instance accepted as fresh")
	}
	events[2].CreatedAt = start.Add(-time.Second)
	if _, ready, e = taskProofFromEvents(task, instance, events); e == nil || ready {
		t.Fatal("reversed native task event times accepted")
	}
}
