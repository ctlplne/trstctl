// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTaskTerminalRecoveryKeepsFailureDistinctFromSuccessA267(t *testing.T) {
	task := ownedTask()
	instance := ownedTaskProof().InstanceID
	events := ownedTaskEvents()
	start := time.Now().UTC()
	for i := range events {
		events[i].CreatedAt = start.Add(time.Duration(i) * time.Millisecond)
	}
	events[1].ResultCode = 1
	proof, ready, err := taskTerminalProofFromEvents(task, instance, events)
	if err != nil || !ready || proof.Actions[0].ResultCode != 1 {
		t.Fatal("terminal native failure was not retained", err)
	}
	if ValidateTaskRunProof(task, proof) == nil {
		t.Fatal("terminal failure became successful work")
	}
	if _, ready, err := taskProofFromEvents(task, instance, events); err == nil || ready {
		t.Fatal("successful-run contract relaxed")
	}
	for name, mutate := range map[string]func([]nativeTaskEvent){
		"foreign SID":      func(v []nativeTaskEvent) { v[0].AccountSID = "S-1-5-21-1-2-3-1002" },
		"foreign instance": func(v []nativeTaskEvent) { v[0].InstanceID = "b1234567-1234-4234-8234-123456789abc" },
		"foreign path":     func(v []nativeTaskEvent) { v[1].Path = "\\other\\task" },
		"missing result":   func(v []nativeTaskEvent) { v[1].ResultPresent = false },
		"undated":          func(v []nativeTaskEvent) { v[0].CreatedAt = time.Time{} },
		"reversed":         func(v []nativeTaskEvent) { v[2].CreatedAt = start.Add(-time.Second) },
		"duplicate":        func(v []nativeTaskEvent) { v[1].RecordID = v[0].RecordID },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]nativeTaskEvent(nil), events...)
			mutate(candidate)
			if _, ready, err := taskTerminalProofFromEvents(task, instance, candidate); err == nil || ready {
				t.Fatal("invalid terminal evidence admitted")
			}
		})
	}
	for n := 0; n < 3; n++ {
		if _, ready, err := taskTerminalProofFromEvents(task, instance, events[:n]); err != nil || ready {
			t.Fatal("partial evidence claimed terminal", err)
		}
	}
}

type terminalTaskDriver struct {
	*ownedTaskDriver
	observed     TaskTerminalObservation
	observations int
}

func (d *terminalTaskDriver) observeTerminal(context.Context, Task, string) (TaskTerminalObservation, bool, error) {
	d.observations++
	return d.observed, true, nil
}
func TestTaskTerminalRecoveryOnlyObservesQuiescentExactInstanceA267(t *testing.T) {
	task := ownedTask()
	proof := ownedTaskProof()
	proof.StartedAt = time.Now().UTC()
	proof.CompletedAt = proof.StartedAt
	d := &terminalTaskDriver{ownedTaskDriver: &ownedTaskDriver{current: task}, observed: TaskTerminalObservation{Proof: proof, Quiescent: true, AllInstancesVisible: true, ObservedAt: time.Now().UTC()}}
	adapter, err := newTasks(d, TaskExecutionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ready, err := adapter.ObserveTerminalInstance(t.Context(), task, proof.InstanceID); err != nil || !ready || d.runs != 0 || d.writes != 0 {
		t.Fatal("read-only terminal recovery ran or changed task", err)
	}
	for name, mutate := range map[string]func(){"running": func() { d.observed.Quiescent = false }, "partial visibility": func() { d.observed.AllInstancesVisible = false }, "changed configuration": func() { d.current.ConfigSHA256 = strings.Repeat("b", 64) }, "foreign result": func() { d.observed.Proof.InstanceID = "b1234567-1234-4234-8234-123456789abc" }} {
		t.Run(name, func(t *testing.T) {
			copy := *d
			current := *d.ownedTaskDriver
			d.ownedTaskDriver = &current
			mutate()
			if _, ready, err := adapter.ObserveTerminalInstance(t.Context(), task, proof.InstanceID); err == nil || ready {
				t.Fatal("unsafe terminal recovery admitted")
			}
			*d = copy
		})
	}
	if d.runs != 0 || d.writes != 0 {
		t.Fatal("terminal observation gained native effects")
	}
}

func FuzzTaskTerminalMetadataA267(f *testing.F) {
	events := ownedTaskEvents()
	anchor := time.Unix(1700000000, 0).UTC()
	for i := range events {
		events[i].CreatedAt = anchor.Add(time.Duration(i) * time.Millisecond)
	}
	raw, _ := json.Marshal(events)
	f.Add(raw)
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"EventID":201,"ResultCode":1}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32<<10 {
			return
		}
		var events []nativeTaskEvent
		if json.Unmarshal(raw, &events) != nil {
			return
		}
		proof, ready, err := taskTerminalProofFromEvents(ownedTask(), ownedTaskProof().InstanceID, events)
		if err == nil && ready {
			if ValidateTaskTerminalProof(ownedTask(), proof) != nil {
				t.Fatal("invalid terminal proof escaped native parser")
			}
			for _, action := range proof.Actions {
				matched := false
				for _, event := range events {
					if event.EventID == 201 && event.RecordID == action.RecordID && event.ResultPresent && event.ResultCode == action.ResultCode {
						matched = true
					}
				}
				if !matched {
					t.Fatal("native result was invented or reclassified")
				}
			}
		}
	})
}
