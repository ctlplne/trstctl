// SPDX-License-Identifier: MPL-2.0

package migration_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

func TestRunTrustBeforeLeafHaltAndNewestFirstRollbackAUD40(t *testing.T) {
	run, actions, err := migration.StartRun(migration.Run{
		ID: "11111111-1111-1111-1111-111111111140",
		Waves: []migration.RunWave{
			{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a"}, {IdentityID: "leaf-b"}}},
			{ID: "fleet", Ordinal: 2, Members: []migration.RunMember{{IdentityID: "leaf-c"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionDistributeTrust, "canary", "leaf-a", "leaf-b")

	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(actions) != 0 {
		t.Fatalf("first trust receipt released issuance: actions=%+v err=%v", actions, err)
	}
	if run.Waves[0].Phase != migration.PhaseVerifyingTrust {
		t.Fatalf("partial trust phase = %s", run.Waves[0].Phase)
	}

	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-b", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionIssueSuccessor, "canary", "leaf-a", "leaf-b")
	if run.Waves[1].Phase != migration.PhasePlanned {
		t.Fatalf("later wave moved before canary live evidence: %s", run.Waves[1].Phase)
	}

	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageSuccessor, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(actions) != 0 {
		t.Fatalf("partial successor evidence advanced the run: actions=%+v err=%v", actions, err)
	}
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-b", Stage: migration.StageSuccessor, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionDistributeTrust, "fleet", "leaf-c")

	// A signed failed trust check stops forward motion and automatically begins
	// the inverse. Every member in the failed fleet wave received an install
	// command, so every member receives a remove command even when its forward
	// receipt has not arrived yet.
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "fleet", IdentityID: "leaf-c", Stage: migration.StageTrust, Verdict: migration.VerdictFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRemoveTrust, "fleet", "leaf-c")
	if run.Status != migration.RunRollingBack || run.RollbackWaveID != "fleet" || run.HaltReason == "" {
		t.Fatalf("failed trust did not enter automatic rollback: %+v", run)
	}

	// Newest-first means the failed fleet's possibly-installed trust is removed
	// before the completed canary's leaf is restored.
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "fleet", IdentityID: "leaf-c", Stage: migration.StageRollbackTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRollbackSuccessor, "canary", "leaf-a", "leaf-b")
	run, actions, _ = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageRollbackSuccessor, Verdict: migration.VerdictVerified,
	})
	if len(actions) != 0 {
		t.Fatalf("partial leaf rollback removed trust early: %+v", actions)
	}
	run, actions, _ = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-b", Stage: migration.StageRollbackSuccessor, Verdict: migration.VerdictVerified,
	})
	assertActionsAUD40(t, actions, migration.ActionRemoveTrust, "canary", "leaf-a", "leaf-b")
	run, _, _ = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageRollbackTrust, Verdict: migration.VerdictVerified,
	})
	run, actions, _ = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-b", Stage: migration.StageRollbackTrust, Verdict: migration.VerdictVerified,
	})
	if len(actions) != 0 || run.Status != migration.RunRolledBack || run.Waves[0].Phase != migration.PhaseRolledBack {
		t.Fatalf("rollback did not finish exactly: status=%s wave=%s actions=%+v", run.Status, run.Waves[0].Phase, actions)
	}
}

func TestFailedSuccessorAutomaticallyRollsBackEveryPublishedMemberAndAcceptsLateReceiptAUD40(t *testing.T) {
	run, _, err := migration.StartRun(migration.Run{ID: "run", Waves: []migration.RunWave{{
		ID: "canary", Ordinal: 1,
		Members: []migration.RunMember{{IdentityID: "leaf-a"}, {IdentityID: "leaf-b"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"leaf-a", "leaf-b"} {
		run, _, err = migration.Observe(run, migration.Observation{
			WaveID: "canary", IdentityID: id, Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	run, actions, err := migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageSuccessor, Verdict: migration.VerdictFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRollbackSuccessor, "canary", "leaf-a", "leaf-b")
	if run.Status != migration.RunRollingBack || run.RollbackStage != migration.StageRollbackSuccessor {
		t.Fatalf("failed successor did not enter leaf rollback: %+v", run)
	}

	// leaf-b was already published before leaf-a failed. Its signed late result
	// must close cleanly without restarting forward progress; its per-identity
	// rollback action is serialized behind this work by the effect lane.
	late, actions, err := migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-b", Stage: migration.StageSuccessor,
		Verdict: migration.VerdictVerified, SuccessorFingerprint: "late-successor",
	})
	if err != nil || len(actions) != 0 || late.Status != migration.RunRollingBack {
		t.Fatalf("late forward receipt during rollback = run=%+v actions=%+v err=%v", late, actions, err)
	}
	halted, actions, err := migration.Observe(late, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageRollbackSuccessor, Verdict: migration.VerdictFailed,
	})
	if err != nil || len(actions) != 0 || halted.Status != migration.RunHalted || halted.RollbackAttempt != 1 {
		t.Fatalf("failed inverse = run=%+v actions=%+v err=%v", halted, actions, err)
	}
	retried, actions, err := migration.StartRollback(halted)
	if err != nil || retried.Status != migration.RunRollingBack || retried.RollbackAttempt != 2 {
		t.Fatalf("retry inverse = run=%+v actions=%+v err=%v", retried, actions, err)
	}
	assertActionsAUD40(t, actions, migration.ActionRollbackSuccessor, "canary", "leaf-a", "leaf-b")
}

func TestIssuedSuccessorIsBoundBeforeLiveVerdictAndSurvivesAutomaticRollbackAUD40(t *testing.T) {
	run, _, err := migration.StartRun(migration.Run{ID: "run", Waves: []migration.RunWave{{
		ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	run, _, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err = migration.RecordSuccessorIssued(run, "canary", "leaf", "successor-fingerprint")
	if err != nil || run.Waves[0].Members[0].SuccessorVerdict != "" {
		t.Fatalf("issued binding changed live verdict: run=%+v err=%v", run, err)
	}
	run, actions, err := migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf", Stage: migration.StageSuccessor, Verdict: migration.VerdictFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRollbackSuccessor, "canary", "leaf")
	if run.Waves[0].Members[0].Binding.SuccessorFingerprint != "successor-fingerprint" {
		t.Fatal("automatic rollback lost the exact issued successor fingerprint")
	}
}

func TestRunRejectsDuplicateStaleAndOutOfPhaseObservationsAUD40(t *testing.T) {
	run, _, err := migration.StartRun(migration.Run{ID: "run", Waves: []migration.RunWave{{
		ID: "wave", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := migration.Observe(run, migration.Observation{
		WaveID: "wave", IdentityID: "leaf", Stage: migration.StageSuccessor, Verdict: migration.VerdictVerified,
	}); err == nil {
		t.Fatal("successor evidence was accepted before trust")
	}
	advanced, actions, err := migration.Observe(run, migration.Observation{
		WaveID: "wave", IdentityID: "leaf", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(actions) != 1 {
		t.Fatalf("trust evidence = actions=%+v err=%v", actions, err)
	}
	replayed, duplicate, err := migration.Observe(advanced, migration.Observation{
		WaveID: "wave", IdentityID: "leaf", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(duplicate) != 0 || replayed.Waves[0].Members[0].TrustVerdict != migration.VerdictVerified {
		t.Fatalf("exact replay changed state: run=%+v actions=%+v err=%v", replayed, duplicate, err)
	}
	if _, _, err := migration.Observe(advanced, migration.Observation{
		WaveID: "wave", IdentityID: "leaf", Stage: migration.StageTrust, Verdict: migration.VerdictFailed,
	}); err == nil {
		t.Fatal("semantic replay drift was accepted")
	}
}

func TestRunRejectsActionsOutsideTheCurrentGateAUD40(t *testing.T) {
	run, actions, err := migration.StartRun(migration.Run{ID: "run", Waves: []migration.RunWave{{
		ID: "wave", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.ValidateActions(run, actions); err != nil {
		t.Fatalf("start actions rejected: %v", err)
	}
	unsafe := append([]migration.Action(nil), actions...)
	unsafe[0].Kind = migration.ActionIssueSuccessor
	if err := migration.ValidateActions(run, unsafe); err == nil {
		t.Fatal("successor issuance was accepted before the trust gate")
	}
	if err := migration.ValidateActions(run, append(actions, actions[0])); err == nil {
		t.Fatal("duplicate action was accepted")
	}
}

func TestPauseRetainsLeasedReceiptAndResumeReleasesOnlyCompletedGateAUD40(t *testing.T) {
	run, _, err := migration.StartRun(migration.Run{ID: "run", Waves: []migration.RunWave{{
		ID: "canary", Ordinal: 1,
		Members: []migration.RunMember{{IdentityID: "leaf-a"}, {IdentityID: "leaf-b"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	run, err = migration.PauseRun(run, "operator hold")
	if err != nil {
		t.Fatal(err)
	}
	run, actions, err := migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(actions) != 0 || run.Status != migration.RunPaused {
		t.Fatalf("paused leased receipt = run=%+v actions=%+v err=%v", run, actions, err)
	}
	run, actions, err = migration.ResumeRun(run)
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionDistributeTrust, "canary", "leaf-b")

	run, err = migration.PauseRun(run, "second hold")
	if err != nil {
		t.Fatal(err)
	}
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-b", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(actions) != 0 || run.Waves[0].Phase != migration.PhaseVerifyingTrust {
		t.Fatalf("completed paused gate advanced early: run=%+v actions=%+v err=%v", run, actions, err)
	}
	run, actions, err = migration.ResumeRun(run)
	if err != nil || run.Waves[0].Phase != migration.PhaseVerifyingLive {
		t.Fatalf("resume did not release retained complete gate: run=%+v actions=%+v err=%v", run, actions, err)
	}
	assertActionsAUD40(t, actions, migration.ActionIssueSuccessor, "canary", "leaf-a", "leaf-b")
}

func TestExecutableRunRefusesOneAgentTrustPathAcrossWavesAUD40(t *testing.T) {
	first := completeBindingAUD40("target-a", "predecessor-a")
	second := completeBindingAUD40("target-b", "predecessor-b")
	run := migration.Run{ID: "run", Waves: []migration.RunWave{
		{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a", Binding: first}}},
		{ID: "fleet", Ordinal: 2, Members: []migration.RunMember{{IdentityID: "leaf-b", Binding: second}}},
	}}
	if err := migration.ValidateExecutableRunForStart(run); err == nil {
		t.Fatal("one agent trust path was accepted in two waves; rollback could remove trust from the still-live older wave")
	}
	run.Waves = []migration.RunWave{{
		ID: "canary", Ordinal: 1,
		Members: []migration.RunMember{{IdentityID: "leaf-a", Binding: first}, {IdentityID: "leaf-b", Binding: second}},
	}}
	if err := migration.ValidateExecutableRunForStart(run); err != nil {
		t.Fatalf("shared path inside one atomically rolled-back wave was refused: %v", err)
	}
}

func TestIncidentRunRevokesOnlyAfterSignedLiveGateBeforeNextCohortAUD41(t *testing.T) {
	first := completeBindingAUD40("target-a", "predecessor-a")
	first.PredecessorCAID = "compromised-authority"
	second := completeBindingAUD40("target-b", "predecessor-b")
	second.PredecessorCAID = "compromised-authority"
	run, actions, err := migration.StartRun(migration.Run{
		ID: "incident-run",
		Incident: &migration.IncidentPlan{
			Mode: migration.IncidentModeLive, CompromisedIssuerID: "compromised-issuer",
			ReplacementAuthorityID: "authority", ExactTrustStoreIDs: []string{"trust-store-a"},
			ExactTrustHosts: []string{"agent-a"}, AffectedIdentityIDs: []string{"leaf-a", "leaf-b"},
		},
		Waves: []migration.RunWave{
			{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a", Binding: first}}},
			{ID: "fleet", Ordinal: 2, Members: []migration.RunMember{{IdentityID: "leaf-b", Binding: second}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionDistributeTrust, "canary", "leaf-a")
	run, _, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageSuccessor,
		Verdict: migration.VerdictVerified, SuccessorFingerprint: "successor-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRevokePredecessor, "canary", "leaf-a")
	if run.Waves[0].Phase != migration.PhaseRevokingPredecessor || run.Waves[1].Started {
		t.Fatalf("live gate advanced before exact revocation: %+v", run)
	}
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "canary", IdentityID: "leaf-a", Stage: migration.StageRevocation, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionDistributeTrust, "fleet", "leaf-b")
}

func TestIncidentFailedCohortRollsBackOnlyThatCohortAUD41(t *testing.T) {
	first := completeBindingAUD40("target-a", "predecessor-a")
	first.PredecessorCAID = "compromised-authority"
	second := completeBindingAUD40("target-b", "predecessor-b")
	second.PredecessorCAID = "compromised-authority"
	run := migration.Run{
		ID: "incident-run", Status: migration.RunRunning,
		Incident: &migration.IncidentPlan{Mode: migration.IncidentModeLive, CompromisedIssuerID: "issuer",
			ReplacementAuthorityID: "authority", ExactTrustStoreIDs: []string{"store"}, ExactTrustHosts: []string{"agent"},
			AffectedIdentityIDs: []string{"leaf-a", "leaf-b"}},
		Waves: []migration.RunWave{
			{ID: "canary", Ordinal: 1, Started: true, Phase: migration.PhaseComplete,
				Members: []migration.RunMember{{IdentityID: "leaf-a", Binding: first,
					TrustVerdict: migration.VerdictVerified, SuccessorVerdict: migration.VerdictVerified,
					RevocationVerdict: migration.VerdictVerified}}},
			{ID: "fleet", Ordinal: 2, Started: true, Phase: migration.PhaseVerifyingLive,
				Members: []migration.RunMember{{IdentityID: "leaf-b", Binding: second,
					TrustVerdict: migration.VerdictVerified}}},
		},
	}
	run, actions, err := migration.Observe(run, migration.Observation{
		WaveID: "fleet", IdentityID: "leaf-b", Stage: migration.StageSuccessor, Verdict: migration.VerdictFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRollbackSuccessor, "fleet", "leaf-b")
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "fleet", IdentityID: "leaf-b", Stage: migration.StageRollbackSuccessor, Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertActionsAUD40(t, actions, migration.ActionRemoveTrust, "fleet", "leaf-b")
	run, actions, err = migration.Observe(run, migration.Observation{
		WaveID: "fleet", IdentityID: "leaf-b", Stage: migration.StageRollbackTrust, Verdict: migration.VerdictVerified,
	})
	if err != nil || len(actions) != 0 || run.Status != migration.RunRolledBack || run.Waves[0].Phase != migration.PhaseComplete {
		t.Fatalf("incident rollback touched a completed revoked cohort: run=%+v actions=%+v err=%v", run, actions, err)
	}
}

func TestGameDayRunStructurallyRefusesProductionBindingsAUD41(t *testing.T) {
	binding := completeBindingAUD40("target-a", "predecessor-a")
	binding.PredecessorCAID = "test-authority"
	binding.Environment = "production"
	run := migration.Run{ID: "game-day", Incident: &migration.IncidentPlan{
		Mode: migration.IncidentModeGameDay, CompromisedIssuerID: "test-issuer",
		ReplacementAuthorityID: "authority", ExactTrustStoreIDs: []string{"store"},
		ExactTrustHosts: []string{"agent"}, AffectedIdentityIDs: []string{"leaf-a"},
	}, Waves: []migration.RunWave{{ID: "test", Ordinal: 1, Members: []migration.RunMember{{IdentityID: "leaf-a", Binding: binding}}}}}
	if err := migration.ValidateExecutableRunForStart(run); err == nil {
		t.Fatal("game-day accepted a production member binding")
	}
	binding.Environment = "test"
	run.Waves[0].Members[0].Binding = binding
	if err := migration.ValidateExecutableRunForStart(run); err != nil {
		t.Fatalf("explicit test cohort was refused: %v", err)
	}
}

func completeBindingAUD40(targetID, predecessorID string) migration.MemberBinding {
	return migration.MemberBinding{
		IssuingAuthorityID: "authority", TargetID: targetID, TargetRevision: "revision",
		Connector: "nginx", Target: targetID, TargetConfig: json.RawMessage(`{"executor":"agent"}`),
		RequiredAgentID: "agent", TrustAnchorPath: "/etc/trstctl/next.pem",
		TrustAnchorPEM: []byte("public"), TrustAnchorFingerprint: "anchor",
		VerifyAddress: "127.0.0.1:443", SubjectCommonName: targetID + ".test",
		SubjectDNSNames: []string{targetID + ".test"}, PredecessorCertificateID: predecessorID,
		PredecessorFingerprint: "predecessor-" + predecessorID,
	}
}

func assertActionsAUD40(t *testing.T, actions []migration.Action, kind migration.ActionKind, waveID string, members ...string) {
	t.Helper()
	if len(actions) != len(members) {
		t.Fatalf("actions = %+v, want %d %s", actions, len(members), kind)
	}
	seen := map[string]bool{}
	for _, action := range actions {
		if action.Kind != kind || action.WaveID != waveID {
			t.Fatalf("action = %+v, want %s/%s", action, kind, waveID)
		}
		seen[action.IdentityID] = true
	}
	for _, member := range members {
		if !seen[member] {
			t.Fatalf("actions %+v omit %s", actions, member)
		}
	}
}
