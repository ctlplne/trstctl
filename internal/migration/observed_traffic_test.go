// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/migration"
)

// X3: a run that requires observed traffic keeps each wave at its live gate
// until both the live receipt and wire evidence of new connections arrived for
// every member; wire evidence cannot be "failed" (its absence pauses the run),
// and a resume releases the gate only once the evidence is there.
func TestObservedTrafficHoldsTheLiveGateX3(t *testing.T) {
	run, _, err := migration.StartRun(migration.Run{
		ID: "33333333-3333-4333-8333-333333333303", RequireObservedTraffic: true, ObservedTrafficWindowSeconds: 600,
		Waves: []migration.RunWave{
			{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a"}}},
			{ID: "fleet", Ordinal: 2, Members: []migration.RunMember{{IdentityID: "leaf-b"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	observe := func(stage migration.ObservationStage, verdict migration.Verdict, at time.Time) ([]migration.Action, error) {
		t.Helper()
		var actions []migration.Action
		run, actions, err = migration.Observe(run, migration.Observation{WaveID: "canary", IdentityID: "leaf-a", Stage: stage, Verdict: verdict, At: at})
		return actions, err
	}
	if _, err := observe(migration.StageTrust, migration.VerdictVerified, time.Time{}); err != nil {
		t.Fatal(err)
	}
	live := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	actions, err := observe(migration.StageSuccessor, migration.VerdictVerified, live)
	if err != nil || len(actions) != 0 || run.Waves[0].Phase != migration.PhaseVerifyingLive {
		t.Fatalf("a live receipt alone advanced the wave: phase %s actions %+v err %v", run.Waves[0].Phase, actions, err)
	}
	member := run.Waves[0].Members[0]
	if member.LiveVerifiedAt == nil || !member.LiveVerifiedAt.Equal(live) {
		t.Fatalf("live receipt time = %v", member.LiveVerifiedAt)
	}
	waiting := migration.AwaitingObservedTraffic(run)
	if len(waiting) != 1 || waiting[0].WaveID != "canary" || waiting[0].Member.IdentityID != "leaf-a" || migration.ObservedTrafficWindow(run) != 10*time.Minute {
		t.Fatalf("awaiting = %+v window %s", waiting, migration.ObservedTrafficWindow(run))
	}
	if _, err := observe(migration.StageObservedTraffic, migration.VerdictFailed, time.Time{}); err == nil {
		t.Fatal("missing wire evidence was recorded as a failed member")
	}

	// The proof did not arrive: the run pauses; a resume without it stays put.
	if run, err = migration.PauseRun(run, "no new connections observed"); err != nil {
		t.Fatal(err)
	}
	if run, actions, err = migration.ResumeRun(run); err != nil || run.Waves[0].Phase != migration.PhaseVerifyingLive || len(actions) != 0 {
		t.Fatalf("resume without wire evidence: phase %s actions %+v err %v", run.Waves[0].Phase, actions, err)
	}

	// Wire evidence completes the gate and opens the next wave.
	actions, err = observe(migration.StageObservedTraffic, migration.VerdictVerified, time.Time{})
	if err != nil || run.Waves[0].Phase != migration.PhaseComplete || len(actions) == 0 || actions[0].WaveID != "fleet" {
		t.Fatalf("wire evidence did not complete the canary: phase %s actions %+v err %v", run.Waves[0].Phase, actions, err)
	}
	if len(migration.AwaitingObservedTraffic(run)) != 0 {
		t.Fatal("a completed member still awaits traffic")
	}

	// A run that does not ask for wire evidence refuses it and advances on the
	// live receipt alone, as before.
	plain, _, err := migration.StartRun(migration.Run{ID: "33333333-3333-4333-8333-333333333304",
		Waves: []migration.RunWave{{ID: "only", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := migration.Observe(plain, migration.Observation{WaveID: "only", IdentityID: "leaf", Stage: migration.StageObservedTraffic, Verdict: migration.VerdictVerified}); err == nil {
		t.Fatal("a run without the requirement accepted wire evidence")
	}
	if _, _, err := migration.StartRun(migration.Run{ID: "33333333-3333-4333-8333-333333333305", ObservedTrafficWindowSeconds: 60,
		Waves: []migration.RunWave{{ID: "only", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf"}}}}}); err == nil {
		t.Fatal("a traffic window without the requirement was accepted")
	}
}
