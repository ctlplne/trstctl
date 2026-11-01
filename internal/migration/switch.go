// SPDX-License-Identifier: BUSL-1.1

package migration

// Planned CA switch (P3). A run with RevokePredecessors moves certificates to a
// new issuer cohort by cohort through the same gates as any migration — trust
// first, then the successor, then the live receipt (and wire evidence when the
// run requires it) — and only then revokes each predecessor through the CA that
// issued it. A failed verification pauses the run before any further cohort or
// revocation; resuming retries exactly the failed members.

// revokesPredecessors reports whether the run revokes each verified member's
// predecessor: every incident run, and a planned switch.
func revokesPredecessors(run Run) bool { return run.Incident != nil || run.RevokePredecessors }

// pausesOnFailure reports whether a failed verification pauses the run instead
// of rolling its cohort back: a planned switch.
func pausesOnFailure(run Run) bool { return run.Incident == nil && run.RevokePredecessors }

// retryFailedMembers clears the failed verdicts of the open cohort's current
// gate and returns the work that retries exactly those members. Each retried
// member's Attempt changes its work's identity, so the retry is new work
// rather than a replay of the failed attempt, and members still pending keep
// the work they already have.
func retryFailedMembers(out *Run) []Action {
	for wi := range out.Waves {
		wave := &out.Waves[wi]
		var stage ObservationStage
		var kind ActionKind
		switch wave.Phase {
		case PhaseVerifyingTrust:
			stage, kind = StageTrust, ActionDistributeTrust
		case PhaseVerifyingLive:
			stage, kind = StageSuccessor, ActionIssueSuccessor
		default:
			continue
		}
		var retry []Action
		for mi := range wave.Members {
			verdict := verdictForStage(&wave.Members[mi], stage)
			if verdict == nil || *verdict != VerdictFailed {
				continue
			}
			*verdict = ""
			wave.Members[mi].Attempt++
			if stage == StageSuccessor {
				wave.Members[mi].LiveVerifiedAt = nil
				wave.Members[mi].TrafficVerdict = ""
			}
			retry = append(retry, Action{Kind: kind, WaveID: wave.ID, IdentityID: wave.Members[mi].IdentityID})
		}
		if len(retry) > 0 {
			wave.HaltReason = ""
			return retry
		}
	}
	return nil
}
