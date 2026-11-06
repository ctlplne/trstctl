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

func workflowFixture(t testing.TB) (RotationIntent, []RotationHostInput) {
	t.Helper()
	now := time.Now().UTC()
	account := AccountBinding{AccountID: "11111111-1111-4111-8111-111111111111", ProviderID: "directory", Name: "svc", DN: "CN=svc,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1001", GUID: strings.Repeat("a", 32)}
	binding := HostBinding{Account: account, AgentID: "22222222-2222-4222-8222-222222222222", Revision: 1, Enabled: true}
	scan, e := NewInventoryIntent("33333333-3333-4333-8333-333333333333", binding)
	if e != nil {
		t.Fatal(e)
	}
	report := InventoryReport{RunID: scan.RunID, BindingDigest: scan.BindingDigest, ObservedAt: now, Coverage: []FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}}, Services: []windependents.Service{
		{Name: "base", AccountSID: account.SID, ConfigSHA256: strings.Repeat("b", 64), WasRunning: true},
		{Name: "child", AccountSID: account.SID, ConfigSHA256: strings.Repeat("c", 64), Dependencies: []string{"base"}, WasRunning: true},
	}, Tasks: []windependents.Task{{Path: "\\owned\\work", AccountSID: account.SID, ConfigSHA256: strings.Repeat("d", 64), Enabled: true, LogonType: 1, ActionCount: 1}}, Pools: []windependents.Pool{{Name: "web", AccountSID: account.SID, ConfigSHA256: strings.Repeat("e", 64), EncryptionProvider: "native", PasswordProtected: true, WasStarted: true}}}
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	input := []RotationHostInput{{Binding: binding, Inventory: report, InventoryDigest: crypto.SHA256Hex(raw)}}
	order := []DependentRef{{binding.AgentID, "services", "base"}, {binding.AgentID, "services", "child"}, {binding.AgentID, "tasks", "\\owned\\work"}, {binding.AgentID, "iis", "web"}}
	plan, e := NewRotationPlan("44444444-4444-4444-8444-444444444444", account, "app/credential", input, order, now)
	if e != nil {
		t.Fatal(e)
	}
	intent := RotationIntent{Plan: plan, ExpectedVersion: 7, ProviderBinding: strings.Repeat("f", 64)}
	for _, ref := range order {
		intent.Probes = append(intent.Probes, ProbeBinding{Ref: ref, ProbeID: "owned-work"})
	}
	return intent, input
}

func TestRotationIntentRequiresFunctionalBindingAndServiceOrder(t *testing.T) {
	intent, inputs := workflowFixture(t)
	if e := intent.Validate(inputs); e != nil {
		t.Fatal(e)
	}
	omitted := intent
	omitted.Probes = omitted.Probes[:3]
	if omitted.Validate(inputs) == nil {
		t.Fatal("rotation omitted useful-work authority")
	}
	duplicate := intent
	duplicate.Probes = append([]ProbeBinding(nil), intent.Probes...)
	duplicate.Probes[3] = duplicate.Probes[0]
	if duplicate.Validate(inputs) == nil {
		t.Fatal("duplicate functional probe replaced a dependent")
	}
	reversed := intent
	order := append([]DependentRef(nil), intent.Plan.Order...)
	order[0], order[1] = order[1], order[0]
	var e error
	reversed.Plan, e = NewRotationPlan(intent.Plan.ID, intent.Plan.Account, intent.Plan.SecretName, inputs, order, intent.Plan.CreatedAt)
	if e != nil {
		t.Fatal(e)
	}
	if reversed.Validate(inputs) == nil {
		t.Fatal("reviewed order starts child before dependency")
	}
	steps, e := intent.Steps(inputs, Forward)
	if e != nil {
		t.Fatal(e)
	}
	var stopped, updated, started []string
	for _, s := range steps {
		if e := s.Validate(); e != nil {
			t.Fatal(e)
		}
		switch s.Action {
		case Stop:
			stopped = append(stopped, s.Ref.Name)
		case Update:
			updated = append(updated, s.Ref.Name)
		case Start:
			started = append(started, s.Ref.Name)
		}
	}
	if strings.Join(stopped, ",") != "web,child,base" || strings.Join(started, ",") != "base,child,web" || len(updated) != 4 {
		t.Fatalf("unsafe phase ordering: stop=%v update=%v start=%v", stopped, updated, started)
	}
	rollback, e := intent.Steps(inputs, Inverse)
	if e != nil || len(rollback) != len(steps)-len(intent.Plan.Order) {
		t.Fatalf("inverse must restore all targets without preflight: %d %v", len(rollback), e)
	}
	for _, step := range rollback {
		if step.Direction != Inverse {
			t.Fatal("inverse reused forward material authority")
		}
	}
}

func TestDependentStepReportCannotClaimUsefulWorkFromIdentityOnly(t *testing.T) {
	intent, inputs := workflowFixture(t)
	steps, e := intent.Steps(inputs, Forward)
	if e != nil {
		t.Fatal(e)
	}
	step := steps[len(steps)-1]
	step.Challenge = "55555555-5555-4555-8555-555555555555"
	step.NotBefore = time.Now().UTC()
	step.Deadline = step.NotBefore.Add(time.Minute)
	report := StepReport{RotationID: step.RotationID, PlanDigest: step.PlanDigest, StepID: step.ID, Direction: step.Direction, Status: "succeeded", ObservedAt: step.NotBefore.Add(time.Second), Runtime: &windependents.Runtime{Running: true, ProcessID: 17, AccountSID: step.AccountSID}}
	if report.Validate(step) == nil {
		t.Fatal("native identity alone became functional completion")
	}
	report.PoolProof = &windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: true, StoppedObserved: true, StartedObserved: true, PreviousPIDs: step.PreviousPIDs}
	report.Functional = &FunctionalProof{Challenge: step.Challenge, ProbeID: step.ProbeID, ProcessID: 17, AccountSID: step.AccountSID, EvidenceSHA256: strings.Repeat("a", 64)}
	if e := report.Validate(step); e != nil {
		t.Fatal(e)
	}
	report.Functional.Challenge = "66666666-6666-4666-8666-666666666666"
	if report.Validate(step) == nil {
		t.Fatal("a stale successful probe satisfied this execution")
	}
}

func TestDependentTaskProbeRefusesAnUndatedNativeInstanceA267(t *testing.T) {
	intent, inputs := workflowFixture(t)
	steps, e := intent.Steps(inputs, Forward)
	if e != nil {
		t.Fatal(e)
	}
	var step RotationStep
	for _, candidate := range steps {
		if candidate.Task != nil && candidate.Action == Probe {
			step = candidate
			break
		}
	}
	step.Challenge = "55555555-5555-4555-8555-555555555555"
	step.NotBefore = time.Now().UTC()
	step.Deadline = step.NotBefore.Add(time.Minute)
	instance := "66666666-6666-4666-8666-666666666666"
	proof := windependents.TaskRunProof{Path: step.Task.Path, AccountSID: step.AccountSID, InstanceID: instance, StartRecordID: 10, CompletionRecordID: 13, Actions: []windependents.TaskActionResult{{RecordID: 12, ResultCode: 0}}}
	report := StepReport{RotationID: step.RotationID, PlanDigest: step.PlanDigest, StepID: step.ID, Direction: step.Direction, Status: "succeeded", ObservedAt: step.NotBefore.Add(time.Second), TaskProof: &proof, Functional: &FunctionalProof{ProbeID: step.ProbeID, Challenge: step.Challenge, AccountSID: step.AccountSID, TaskInstanceID: instance, EvidenceSHA256: strings.Repeat("a", 64)}}
	if e = report.Validate(step); e == nil {
		t.Fatal("a historical undated native task instance satisfied current useful work")
	}
	proof.StartedAt = step.NotBefore
	proof.CompletedAt = report.ObservedAt
	if e = report.Validate(step); e != nil {
		t.Fatal("fresh native task work refused", e)
	}
	for _, mutate := range []func(*windependents.TaskRunProof){
		func(p *windependents.TaskRunProof) { p.StartedAt = step.NotBefore.Add(-time.Second) },
		func(p *windependents.TaskRunProof) { p.CompletedAt = report.ObservedAt.Add(time.Second) },
		func(p *windependents.TaskRunProof) { p.StartedAt = time.Time{} },
		func(p *windependents.TaskRunProof) { p.CompletedAt = time.Time{} },
	} {
		candidate := proof
		mutate(&candidate)
		report.TaskProof = &candidate
		if e = report.Validate(step); e == nil {
			t.Fatal("native task evidence escaped the exact execution lease")
		}
	}

}
