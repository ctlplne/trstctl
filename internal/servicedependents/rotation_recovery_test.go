// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

func ownedRecoveryStep() RotationStep {
	step := RotationStep{RotationID: "57800000-0000-4000-8000-000000000001", PlanDigest: strings.Repeat("a", 64), Direction: Inverse, Action: Probe, Ref: DependentRef{AgentID: "57800000-0000-4000-8000-000000000002", Family: "tasks", Name: "\\owned\\task"}, AccountSID: "S-1-5-21-1-2-3-1001", ProbeID: "owned-work", Task: &windependents.Task{Path: "\\owned\\task", AccountSID: "S-1-5-21-1-2-3-1001", ConfigSHA256: strings.Repeat("b", 64), Enabled: true, LogonType: 1, ActionCount: 1}, Challenge: "57800000-0000-4000-8000-000000000003", NotBefore: time.Unix(1700000000, 0).UTC(), Deadline: time.Unix(1700000120, 0).UTC()}
	step.ID = crypto.SHA256Hex([]byte(step.RotationID + "\x00" + step.PlanDigest + "\x00" + step.Direction + "\x00" + step.Action + "\x00" + dependentKey(step.Ref)))[:32]
	return step
}
func TestInverseRecoveryStepKeepsExactEffectAndOrdinaryEncodingA267(t *testing.T) {
	previous := ownedRecoveryStep()
	if e := previous.Validate(); e != nil {
		t.Fatal(e)
	}
	before, e := json.Marshal(previous)
	if e != nil {
		t.Fatal(e)
	}
	now := previous.Deadline.Add(time.Hour)
	challenge := "57800000-0000-4000-8000-000000000004"
	if _, err := NewInverseRecoveryStep(previous, previous.Challenge, now); err == nil {
		t.Fatal("recovery reused the predecessor challenge")
	}
	next, e := NewInverseRecoveryStep(previous, challenge, now)
	if e != nil || next.Validate() != nil || next.ID == previous.ID || next.Recovery == nil || next.Recovery.PreviousStepID != previous.ID || next.Recovery.RootStepID != previous.ID || !next.NotBefore.Equal(now) || !next.Deadline.Equal(now.Add(2*time.Minute)) {
		t.Fatal("fresh inverse recovery identity or lease differs", e)
	}
	if next.PlanDigest != previous.PlanDigest || next.RotationID != previous.RotationID || next.Ref != previous.Ref || next.AccountSID != previous.AccountSID || next.ProbeID != previous.ProbeID || *next.Task != *previous.Task {
		t.Fatal("recovery changed a native effect")
	}
	after, _ := json.Marshal(previous)
	if string(before) != string(after) || strings.Contains(string(before), `"recovery"`) {
		t.Fatal("ordinary frozen step was changed")
	}
	next.Task.ConfigSHA256 = strings.Repeat("c", 64)
	if previous.Task.ConfigSHA256 != strings.Repeat("b", 64) {
		t.Fatal("replacement aliases caller's native snapshot")
	}
	next, e = NewInverseRecoveryStep(previous, challenge, now)
	if e != nil {
		t.Fatal(e)
	}
	further, e := NewInverseRecoveryStep(next, "57800000-0000-4000-8000-000000000005", now.Add(time.Hour))
	if e != nil || further.ID == next.ID || further.Recovery.RootStepID != previous.ID || further.Recovery.PreviousStepID != next.ID {
		t.Fatal("replacement lineage lost original authority", e)
	}
	foreign := previous
	foreign.Direction = Forward
	foreign.ID = crypto.SHA256Hex([]byte(foreign.RotationID + "\x00" + foreign.PlanDigest + "\x00" + foreign.Direction + "\x00" + foreign.Action + "\x00" + dependentKey(foreign.Ref)))[:32]
	if foreign.Validate() != nil {
		t.Fatal("forward refusal fixture is invalid")
	}
	if _, e = NewInverseRecoveryStep(foreign, challenge, now); e == nil {
		t.Fatal("forward work gained recovery authority")
	}
	forged := next
	copy := *next.Recovery
	forged.Recovery = &copy
	forged.Recovery.RootStepID = strings.Repeat("d", 32)
	if forged.Validate() == nil {
		t.Fatal("foreign recovery root accepted")
	}
}
