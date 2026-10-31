// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

func cloudStoreBindingA166(targetID, predecessorID string) migration.MemberBinding {
	binding := completeBindingAUD40(targetID, predecessorID)
	binding.Connector, binding.Target = "gcp-certificate-manager", targetID
	binding.TargetConfig = json.RawMessage(`{"project":"p","location":"global","certificate_map_entry":"web-map/web-entry"}`)
	binding.RequiredAgentID = ""
	binding.TrustAnchorPath = ""
	binding.VerifyAddress = ""
	binding.ExecutionModel = migration.ExecutionCloudStore
	return binding
}

// A166: a cloud certificate store joins a run with no agent. The control plane
// carries its store, so the binding names none and its target is assigned to
// none; like an appliance it has no trust stage, so a cohort of cloud stores
// opens at the leaf gate, and its rollback re-binds the predecessor without an
// anchor to remove.
func TestCloudStoreMembersRunWithoutAnAgent(t *testing.T) {
	t.Run("a cloud-store cohort opens at the leaf gate and rolls back without a trust stage", func(t *testing.T) {
		run := migration.Run{ID: "run-a166", Waves: []migration.RunWave{{
			ID: "cloud", Ordinal: 1,
			Members: []migration.RunMember{{IdentityID: "store-1", Binding: cloudStoreBindingA166("store-1", "pred-1")}},
		}}}
		if err := migration.ValidateExecutableRunForStart(run); err != nil {
			t.Fatalf("cloud-store member was refused: %v", err)
		}
		started, actions, err := migration.StartRun(run)
		if err != nil {
			t.Fatal(err)
		}
		member := started.Waves[0].Members[0]
		if started.Waves[0].Phase != migration.PhaseVerifyingLive || member.TrustVerdict != migration.VerdictNotApplicable ||
			!member.Binding.OnControlPlane() || member.Binding.HasTrustStage() {
			t.Fatalf("started wave = phase %s trust %q", started.Waves[0].Phase, member.TrustVerdict)
		}
		if got := kindsOf(actions); len(got) != 1 || got[0] != "issue_successor:store-1" {
			t.Fatalf("start actions = %v, want only the cloud-store successor", got)
		}
		issued, err := migration.RecordSuccessorIssued(started, "cloud", "store-1", "succ-1")
		if err != nil {
			t.Fatal(err)
		}
		// The store read back something other than the successor: the gate
		// fails and the run rolls the member back, with no trust to remove.
		failed, actions, err := migration.Observe(issued, migration.Observation{WaveID: "cloud", IdentityID: "store-1", Stage: migration.StageSuccessor, Verdict: migration.VerdictFailed})
		if err != nil {
			t.Fatal(err)
		}
		if failed.Status != migration.RunRollingBack {
			t.Fatalf("after a failed gate: status %s", failed.Status)
		}
		if got := kindsOf(actions); len(got) != 1 || got[0] != "rollback_successor:store-1" {
			t.Fatalf("rollback actions = %v, want the re-bind only", got)
		}
		rolled, actions, err := migration.Observe(failed, migration.Observation{WaveID: "cloud", IdentityID: "store-1", Stage: migration.StageRollbackSuccessor, Verdict: migration.VerdictVerified})
		if err != nil {
			t.Fatal(err)
		}
		if rolled.Status != migration.RunRolledBack || len(actions) != 0 ||
			rolled.Waves[0].Members[0].RollbackTrustVerdict != migration.VerdictNotApplicable {
			t.Fatalf("after the verified re-bind: status %s actions %v member %+v", rolled.Status, kindsOf(actions), rolled.Waves[0].Members[0])
		}
	})
	t.Run("a cloud-store binding names no agent, no trust path and no agent-assigned target", func(t *testing.T) {
		for name, mutate := range map[string]func(*migration.MemberBinding){
			"an agent":          func(b *migration.MemberBinding) { b.RequiredAgentID = "relay" },
			"a trust path":      func(b *migration.MemberBinding) { b.TrustAnchorPath = "/etc/trstctl/next.pem" },
			"an agent executor": func(b *migration.MemberBinding) { b.TargetConfig = json.RawMessage(`{"executor":"agent"}`) },
			"a relay target":    func(b *migration.MemberBinding) { b.TargetConfig = json.RawMessage(`{"required_agent_id":"relay"}`) },
		} {
			t.Run(name, func(t *testing.T) {
				binding := cloudStoreBindingA166("store-1", "pred-1")
				mutate(&binding)
				run := migration.Run{ID: "run-a166-bad", Waves: []migration.RunWave{{ID: "w", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "store-1", Binding: binding}}}}}
				if err := migration.ValidateExecutableRunForStart(run); err == nil {
					t.Fatalf("a cloud-store member with %s was admitted", name)
				}
			})
		}
		// An appliance or host member still needs its agent.
		host := completeBindingAUD40("web-1", "pred-h")
		host.RequiredAgentID = ""
		run := migration.Run{ID: "run-a166-host", Waves: []migration.RunWave{{ID: "w", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "web-1", Binding: host}}}}}
		if err := migration.ValidateExecutableRunForStart(run); err == nil {
			t.Fatal("a host member without an agent was admitted")
		}
	})
}
