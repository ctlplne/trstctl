// SPDX-License-Identifier: BUSL-1.1

package compatlab

import (
	"strings"
	"testing"
)

func cohort(targeted []string, rs ...Result) Cohort {
	return Cohort{Name: "wave-1", Targeted: targeted, Results: rs}
}

// The dangerous failure: a cohort that was never really exercised reporting
// zero failures, and somebody reading that as "PQ is safe to roll out".
func TestAClientNeverHandshakedMakesTheCohortIncomplete(t *testing.T) {
	t.Parallel()
	v := Assess(cohort([]string{"a", "b", "c"},
		Result{ClientID: "a", Outcome: OutcomeNegotiated},
		Result{ClientID: "b", Outcome: OutcomeNegotiated}))
	if v.Ready {
		t.Fatal("a cohort reported READY while one targeted client was never handshaked.\n\n" +
			"Silence is not compatibility. A wave that reached two of three clients must not " +
			"report on the third — that is how a migration nobody can easily reverse gets " +
			"certified on evidence that does not exist.")
	}
	if !strings.Contains(v.Summary, "never handshaked") {
		t.Errorf("the verdict does not name what is missing: %q", v.Summary)
	}
	if v.NotAttempted != 1 {
		t.Errorf("not_attempted = %d, want 1", v.NotAttempted)
	}
}

// Unreachable is neither success nor rejection.
func TestUnreachableIsNeitherSuccessNorRejection(t *testing.T) {
	t.Parallel()
	v := Assess(cohort([]string{"a", "b"},
		Result{ClientID: "a", Outcome: OutcomeNegotiated},
		Result{ClientID: "b", Outcome: OutcomeUnreachable}))
	if v.Ready {
		t.Fatal("an unreachable client was counted toward readiness. It says NOTHING about PQ " +
			"compatibility, so it cannot be netted into the success column")
	}
	if v.Halt {
		t.Fatal("an unreachable client halted the wave. It is not a rejection either — treating " +
			"it as one stops a rollout on a network problem and teaches operators to ignore halts")
	}
	if v.Unreachable != 1 || v.Negotiated != 1 {
		t.Fatalf("verdict = %+v", v)
	}
}

// One rejection halts. A PQ rollout breaks connections that used to work.
func TestOneRejectionHaltsTheWave(t *testing.T) {
	t.Parallel()
	for _, n := range []int{2, 50, 500} {
		targeted := make([]string, n)
		results := make([]Result, n)
		for i := range targeted {
			targeted[i] = string(rune('a'+i%26)) + string(rune('0'+i/26))
			results[i] = Result{ClientID: targeted[i], Outcome: OutcomeNegotiated}
		}
		results[0].Outcome = OutcomeRejected
		v := Assess(cohort(targeted, results...))
		if !v.Halt {
			t.Fatalf("a single rejection in a cohort of %d did not halt.\n\n"+
				"A percentage tolerance lets a lab certify a migration that is already breaking "+
				"connections which work today.", n)
		}
		if v.Ready {
			t.Fatalf("a cohort with a rejection reported ready")
		}
	}
}

// A cohort that demonstrated nothing is not evidence of readiness, however few
// failures it recorded.
func TestACohortThatNegotiatedNothingIsNotReady(t *testing.T) {
	t.Parallel()
	v := Assess(cohort([]string{"a"}, Result{ClientID: "a", Outcome: OutcomeUnreachable}))
	if v.Ready {
		t.Fatal("a cohort where nothing negotiated reported ready. Zero failures out of zero " +
			"attempts is not a compatibility finding")
	}
	empty := Assess(cohort(nil))
	if empty.Ready {
		t.Fatal("an empty cohort reported ready — the strongest possible version of certifying " +
			"a migration on no evidence")
	}
}

// The healthy path must work, or the rule is only a refusal.
func TestAFullyNegotiatedCohortIsReady(t *testing.T) {
	t.Parallel()
	v := Assess(cohort([]string{"a", "b"},
		Result{ClientID: "a", Outcome: OutcomeNegotiated},
		Result{ClientID: "b", Outcome: OutcomeNegotiated}))
	if !v.Ready || v.Halt {
		t.Fatalf("a fully negotiated cohort was refused: %+v", v)
	}
}

// A halt must outrank an incompleteness report: a rejection is the more urgent
// fact, and burying it under "some clients were missed" loses it.
func TestARejectionOutranksAnIncompleteCohort(t *testing.T) {
	t.Parallel()
	v := Assess(cohort([]string{"a", "b", "c"},
		Result{ClientID: "a", Outcome: OutcomeRejected}))
	if !v.Halt {
		t.Fatal("a rejection was buried under the incompleteness report. The refusal is the more " +
			"urgent fact and must lead")
	}
}
