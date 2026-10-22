// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

func applianceBindingA33(targetID, predecessorID string) migration.MemberBinding {
	binding := completeBindingAUD40(targetID, predecessorID)
	binding.Connector, binding.Target = "f5", "/Common/"+targetID
	binding.TargetConfig = json.RawMessage(`{"executor":"agent","endpoint":"https://f5.internal","required_agent_id":"relay"}`)
	binding.RequiredAgentID = "relay"
	binding.TrustAnchorPath = ""
	binding.ExecutionModel = migration.ExecutionAppliance
	return binding
}

func kindsOf(actions []migration.Action) []string {
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		out = append(out, string(action.Kind)+":"+action.IdentityID)
	}
	return out
}

// A33: an appliance member has no trust stage — a relay cannot write a trust
// store on an appliance — so a cohort of only appliances opens at the leaf gate,
// its trust verdict honestly reads not_applicable, and its rollback removes no
// anchor. A mixed cohort still gates every leaf on the hosts' trust verdicts.
func TestApplianceMembersSkipTheTrustStagesHonestly(t *testing.T) {
	t.Run("an all-appliance cohort opens at the leaf gate and rolls back without a trust stage", func(t *testing.T) {
		run := migration.Run{ID: "run-a33", Waves: []migration.RunWave{{
			ID: "edge", Ordinal: 1,
			Members: []migration.RunMember{{IdentityID: "lb-1", Binding: applianceBindingA33("lb-1", "pred-1")}},
		}}}
		if err := migration.ValidateExecutableRunForStart(run); err != nil {
			t.Fatalf("appliance member without a trust path was refused: %v", err)
		}
		started, actions, err := migration.StartRun(run)
		if err != nil {
			t.Fatal(err)
		}
		if started.Waves[0].Phase != migration.PhaseVerifyingLive || started.Waves[0].Members[0].TrustVerdict != migration.VerdictNotApplicable {
			t.Fatalf("started wave = phase %s trust %q, want the leaf gate with trust not_applicable", started.Waves[0].Phase, started.Waves[0].Members[0].TrustVerdict)
		}
		if got := kindsOf(actions); len(got) != 1 || got[0] != "issue_successor:lb-1" {
			t.Fatalf("start actions = %v, want only the appliance successor", got)
		}
		if err := migration.ValidateExecutableRun(started); err != nil {
			t.Fatalf("started run invalid: %v", err)
		}
		issued, err := migration.RecordSuccessorIssued(started, "edge", "lb-1", "succ-1")
		if err != nil {
			t.Fatal(err)
		}
		done, actions, err := migration.Observe(issued, migration.Observation{WaveID: "edge", IdentityID: "lb-1", Stage: migration.StageSuccessor, Verdict: migration.VerdictVerified, SuccessorFingerprint: "succ-1"})
		if err != nil {
			t.Fatal(err)
		}
		if done.Status != migration.RunComplete || len(actions) != 0 {
			t.Fatalf("after the verified successor: status %s actions %v", done.Status, kindsOf(actions))
		}
		rolling, actions, err := migration.StartRollback(done)
		if err != nil {
			t.Fatal(err)
		}
		if got := kindsOf(actions); len(got) != 1 || got[0] != "rollback_successor:lb-1" {
			t.Fatalf("rollback actions = %v, want the appliance re-bind", got)
		}
		rolled, actions, err := migration.Observe(rolling, migration.Observation{WaveID: "edge", IdentityID: "lb-1", Stage: migration.StageRollbackSuccessor, Verdict: migration.VerdictVerified})
		if err != nil {
			t.Fatal(err)
		}
		if rolled.Status != migration.RunRolledBack || len(actions) != 0 || rolled.Waves[0].Members[0].RollbackTrustVerdict != migration.VerdictNotApplicable {
			t.Fatalf("after the appliance re-bind: status %s actions %v rollback trust %q", rolled.Status, kindsOf(actions), rolled.Waves[0].Members[0].RollbackTrustVerdict)
		}
	})
	t.Run("a mixed cohort gates every leaf on the hosts' trust and never asks the relay for an anchor", func(t *testing.T) {
		host := completeBindingAUD40("web-1", "pred-h")
		run := migration.Run{ID: "run-a33-mixed", Waves: []migration.RunWave{{
			ID: "edge", Ordinal: 1,
			Members: []migration.RunMember{
				{IdentityID: "web-1", Binding: host},
				{IdentityID: "lb-1", Binding: applianceBindingA33("lb-1", "pred-1")},
			},
		}}}
		started, actions, err := migration.StartRun(run)
		if err != nil {
			t.Fatal(err)
		}
		if got := kindsOf(actions); len(got) != 1 || got[0] != "distribute_trust:web-1" {
			t.Fatalf("start actions = %v, want trust for the host only", got)
		}
		if started.Waves[0].Phase != migration.PhaseVerifyingTrust {
			t.Fatalf("mixed wave phase = %s, want verifying_trust", started.Waves[0].Phase)
		}
		if got := kindsOf(migration.ReconcileActions(started)); len(got) != 1 || got[0] != "distribute_trust:web-1" {
			t.Fatalf("reconcile = %v, want the host trust only", got)
		}
		trusted, actions, err := migration.Observe(started, migration.Observation{WaveID: "edge", IdentityID: "web-1", Stage: migration.StageTrust, Verdict: migration.VerdictVerified})
		if err != nil {
			t.Fatal(err)
		}
		if trusted.Waves[0].Phase != migration.PhaseVerifyingLive {
			t.Fatalf("after host trust: phase %s", trusted.Waves[0].Phase)
		}
		if got := kindsOf(actions); len(got) != 2 || got[0] != "issue_successor:web-1" || got[1] != "issue_successor:lb-1" {
			t.Fatalf("leaf actions = %v, want both successors", got)
		}
		// A trust receipt for the appliance conflicts with its engine-set verdict.
		if _, _, err := migration.Observe(started, migration.Observation{WaveID: "edge", IdentityID: "lb-1", Stage: migration.StageTrust, Verdict: migration.VerdictVerified}); err == nil {
			t.Fatal("a trust receipt for an appliance member was accepted")
		}
	})
	t.Run("a host member still needs its trust path and an appliance target must name its relay", func(t *testing.T) {
		host := completeBindingAUD40("web-1", "pred-h")
		host.TrustAnchorPath = ""
		run := migration.Run{ID: "run-a33-host", Waves: []migration.RunWave{{ID: "w", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "web-1", Binding: host}}}}}
		if err := migration.ValidateExecutableRunForStart(run); err == nil {
			t.Fatal("a host member without a trust path was admitted")
		}
		appliance := applianceBindingA33("lb-1", "pred-1")
		appliance.TargetConfig = json.RawMessage(`{"executor":"agent","required_agent_id":"other-relay"}`)
		run = migration.Run{ID: "run-a33-relay", Waves: []migration.RunWave{{ID: "w", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "lb-1", Binding: appliance}}}}}
		if err := migration.ValidateExecutableRunForStart(run); err == nil {
			t.Fatal("an appliance target naming another relay was admitted")
		}
		appliance.TargetConfig = json.RawMessage(`{"executor":"agent"}`)
		run.Waves[0].Members[0].Binding = appliance
		if err := migration.ValidateExecutableRunForStart(run); err == nil {
			t.Fatal("an appliance target naming no relay was admitted: credential redemption would refuse it")
		}
		appliance.ExecutionModel = "cloud"
		run.Waves[0].Members[0].Binding = appliance
		if err := migration.ValidateExecutableRunForStart(run); err == nil {
			t.Fatal("an unknown execution model was admitted")
		}
	})
}
