// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/migration"
)

// P3: a planned switch revokes each predecessor only after its successor is
// verified live; a failed canary pauses the run with nothing further
// published; resuming retries exactly the failed member; the finished switch
// cannot be rolled back past its revocations.
func TestPlannedSwitchRevokesAfterLiveAndPausesOnAFailedCanaryP3(t *testing.T) {
	run, actions, err := migration.StartRun(migration.Run{
		ID: "33333333-3333-4333-8333-3333333333f3", RevokePredecessors: true,
		Waves: []migration.RunWave{
			{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a"}}},
			{ID: "fleet", Ordinal: 2, Members: []migration.RunMember{{IdentityID: "leaf-b"}, {IdentityID: "leaf-c"}}},
		},
	})
	if err != nil || len(actions) != 1 || actions[0].Kind != migration.ActionDistributeTrust {
		t.Fatalf("start: %+v %v", actions, err)
	}
	observe := func(wave, id string, stage migration.ObservationStage, verdict migration.Verdict) []migration.Action {
		t.Helper()
		var out []migration.Action
		run, out, err = migration.Observe(run, migration.Observation{WaveID: wave, IdentityID: id, Stage: stage, Verdict: verdict, At: time.Now()})
		if err != nil {
			t.Fatalf("%s %s %s %s: %v", wave, id, stage, verdict, err)
		}
		for _, a := range out {
			if a.Kind == migration.ActionRevokePredecessor && stage != migration.StageSuccessor {
				t.Fatalf("revocation published at %s, not after the live receipt", stage)
			}
		}
		return out
	}
	kinds := func(actions []migration.Action) string {
		var out []string
		for _, a := range actions {
			out = append(out, string(a.Kind)+":"+a.IdentityID)
		}
		return strings.Join(out, ",")
	}

	if got := kinds(observe("canary", "leaf-a", migration.StageTrust, migration.VerdictVerified)); got != "issue_successor:leaf-a" {
		t.Fatalf("after trust: %s", got)
	}
	// The canary fails: the run pauses, nothing is revoked, the fleet waits.
	if got := observe("canary", "leaf-a", migration.StageSuccessor, migration.VerdictFailed); len(got) != 0 ||
		run.Status != migration.RunPaused || !strings.Contains(run.PauseReason, "leaf-a") || run.Waves[1].Started {
		t.Fatalf("a failed canary: status %s reason %q actions %s fleet started %v", run.Status, run.PauseReason, kinds(got), run.Waves[1].Started)
	}
	// Resume retries exactly the failed member as new work.
	run, actions, err = migration.ResumeRun(run)
	if err != nil || kinds(actions) != "issue_successor:leaf-a" || run.Waves[0].Members[0].Attempt != 1 || run.Status != migration.RunRunning {
		t.Fatalf("resume: %s attempt %d status %s err %v", kinds(actions), run.Waves[0].Members[0].Attempt, run.Status, err)
	}
	if got := kinds(observe("canary", "leaf-a", migration.StageSuccessor, migration.VerdictVerified)); got != "revoke_predecessor:leaf-a" {
		t.Fatalf("after the canary's live receipt: %s", got)
	}
	if got := kinds(observe("canary", "leaf-a", migration.StageRevocation, migration.VerdictVerified)); got != "distribute_trust:leaf-b,distribute_trust:leaf-c" {
		t.Fatalf("after the canary's revocation: %s", got)
	}
	observe("fleet", "leaf-b", migration.StageTrust, migration.VerdictVerified)
	observe("fleet", "leaf-c", migration.StageTrust, migration.VerdictVerified)
	observe("fleet", "leaf-b", migration.StageSuccessor, migration.VerdictVerified)
	if got := kinds(observe("fleet", "leaf-c", migration.StageSuccessor, migration.VerdictVerified)); got != "revoke_predecessor:leaf-b,revoke_predecessor:leaf-c" {
		t.Fatalf("after the fleet's live receipts: %s", got)
	}
	observe("fleet", "leaf-b", migration.StageRevocation, migration.VerdictVerified)
	observe("fleet", "leaf-c", migration.StageRevocation, migration.VerdictVerified)
	if run.Status != migration.RunComplete {
		t.Fatalf("status %s", run.Status)
	}
	if _, _, err := migration.StartRollback(run); err == nil {
		t.Fatal("a finished switch rolled back past its revocations")
	}
	if _, _, err := migration.Observe(run, migration.Observation{WaveID: "fleet", IdentityID: "leaf-b", Stage: migration.StageSuccessor, Verdict: migration.VerdictFailed}); err == nil {
		t.Fatal("a late verdict conflicting with the retained one was accepted")
	}
}

// P3: a later cohort's failure can be rolled back alone; the cohort that
// finished keeps its revoked predecessors and is not rolled back.
func TestPlannedSwitchRollsBackOnlyTheUnrevokedCohortP3(t *testing.T) {
	run, _, err := migration.StartRun(migration.Run{
		ID: "33333333-3333-4333-8333-3333333333f4", RevokePredecessors: true,
		Waves: []migration.RunWave{
			{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a"}}},
			{ID: "fleet", Ordinal: 2, Members: []migration.RunMember{{IdentityID: "leaf-b"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []migration.Observation{
		{WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageTrust, Verdict: migration.VerdictVerified},
		{WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageSuccessor, Verdict: migration.VerdictVerified},
		{WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageRevocation, Verdict: migration.VerdictVerified},
		{WaveID: "fleet", IdentityID: "leaf-b", Stage: migration.StageTrust, Verdict: migration.VerdictVerified},
		{WaveID: "fleet", IdentityID: "leaf-b", Stage: migration.StageSuccessor, Verdict: migration.VerdictFailed},
	} {
		if run, _, err = migration.Observe(run, o); err != nil {
			t.Fatal(err)
		}
	}
	if run.Status != migration.RunPaused {
		t.Fatalf("status %s", run.Status)
	}
	run, actions, err := migration.StartRollback(run)
	if err != nil || run.RollbackWaveID != "fleet" || len(actions) != 1 || actions[0].IdentityID != "leaf-b" {
		t.Fatalf("rollback: wave %q actions %+v err %v", run.RollbackWaveID, actions, err)
	}
}
