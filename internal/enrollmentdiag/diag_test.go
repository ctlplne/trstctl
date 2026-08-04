// SPDX-License-Identifier: MPL-2.0

package enrollmentdiag_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/enrollmentdiag"
)

// Diagnostics that name a step, a cause, and something to do (epic I4).
//
// The failure this package exists to prevent is a confident wrong answer. An
// operator sent to check DNS because the system pattern-matched an error string
// will spend an hour there before doubting it, and that hour is the entire cost
// of guessing. So "unknown" is a first-class value with no remediation, and the
// tests are mostly about keeping it that way.

func TestEveryCauseCarriesWordsSomebodyCanActOn(t *testing.T) {
	t.Parallel()
	for _, cause := range enrollmentdiag.Causes() {
		d := enrollmentdiag.Diagnose(enrollmentdiag.ProtocolACME, enrollmentdiag.StepValidation, cause)
		if strings.TrimSpace(d.Summary) == "" {
			t.Errorf("cause %q has no summary; a diagnosis with no words is a log line", cause)
		}
		if cause == enrollmentdiag.CauseUnknown {
			// The one that must NOT have a remediation.
			if d.Remediation != "" {
				t.Error("the unknown cause carries a remediation; inventing an action for a " +
					"failure we could not place is exactly the confident wrong answer this " +
					"package exists to avoid")
			}
			if d.Actionable() {
				t.Error("an unplaced failure reports as actionable")
			}
			continue
		}
		if strings.TrimSpace(d.Remediation) == "" {
			t.Errorf("cause %q names no remediation; the step and the cause without an action is "+
				"two thirds of a diagnosis", cause)
		}
		if !d.Actionable() {
			t.Errorf("cause %q is not reported actionable despite carrying a remediation", cause)
		}
	}
}

// A cause outside the closed set is reported AS unknown, not passed through.
// Otherwise a caller could smuggle free text into a set whose whole value is
// that every member has a vetted action.
func TestAnUnrecognizedCauseCollapsesToUnknown(t *testing.T) {
	t.Parallel()
	d := enrollmentdiag.Diagnose(
		enrollmentdiag.ProtocolEST, enrollmentdiag.StepIssue, enrollmentdiag.Cause("made up"))
	if d.Cause != enrollmentdiag.CauseUnknown {
		t.Fatalf("cause = %q, want unknown; a free-text cause would read as a diagnosis and name "+
			"nothing to do", d.Cause)
	}
	if d.Step != enrollmentdiag.StepUnknownStep {
		t.Errorf("step = %q; a failure we cannot place must not claim a step either", d.Step)
	}
	if d.Actionable() {
		t.Error("a made-up cause reported as actionable")
	}
}

// The remediation has to say the thing that is actually hard to work out. These
// assertions pin the specific insight, not the wording.
func TestRemediationsNameTheNonObviousCause(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cause enrollmentdiag.Cause
		must  string
		why   string
	}{
		{
			enrollmentdiag.CauseChallengeNotVisible, "split-horizon",
			"the record looks correct from inside, which is why people check internally and " +
				"conclude the CA is wrong",
		},
		{
			enrollmentdiag.CauseChainIncomplete, "cold trust store",
			"clients that already cache the intermediate succeed and hide the problem",
		},
		{
			enrollmentdiag.CauseResponderUnreachable, "vantage",
			"a responder visible to the control plane can be blocked from the segment that needs it",
		},
		{
			enrollmentdiag.CauseRateLimited, "count failures",
			"a retry loop against a rate limit extends the window rather than clearing it",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.cause), func(t *testing.T) {
			t.Parallel()
			d := enrollmentdiag.Diagnose(enrollmentdiag.ProtocolACME, enrollmentdiag.StepValidation, tc.cause)
			if !strings.Contains(strings.ToLower(d.Remediation), tc.must) {
				t.Errorf("the %q remediation does not mention %q: %s\nit matters because %s",
					tc.cause, tc.must, d.Remediation, tc.why)
			}
		})
	}
}

// Prove-fixed points at VERIFICATION, not at a retry. A successful retry proves
// issuance worked and says nothing about whether the endpoint serves it.
func TestProveFixedCarriesAVerificationReference(t *testing.T) {
	t.Parallel()
	d := enrollmentdiag.Diagnose(
		enrollmentdiag.ProtocolACME, enrollmentdiag.StepValidation,
		enrollmentdiag.CauseChallengeNotVisible).WithProveFixed("endpoint:api.example.test:443")
	if d.ProveFixedRef != "endpoint:api.example.test:443" {
		t.Fatalf("prove-fixed ref = %q", d.ProveFixedRef)
	}
	if strings.Contains(d.Describe(), "prove") {
		t.Error("the one-line description leaks the prove-fixed ref into support-bundle text")
	}
}

// The one-line render distinguishes actionable from not, so a support bundle
// does not read as though every line has an answer.
func TestTheOneLineRenderShowsWhenThereIsNoAction(t *testing.T) {
	t.Parallel()
	unknown := enrollmentdiag.Diagnose(
		enrollmentdiag.ProtocolSCEP, enrollmentdiag.StepUnknownStep, enrollmentdiag.CauseUnknown)
	if strings.Contains(unknown.Describe(), "—") {
		t.Error("an unplaced failure renders with a remediation separator, implying an action " +
			"that is not there")
	}
	actionable := enrollmentdiag.Diagnose(
		enrollmentdiag.ProtocolADCS, enrollmentdiag.StepAuthorize, enrollmentdiag.CauseTemplateACLDenied)
	if !strings.Contains(actionable.Describe(), "Enroll permission") {
		t.Errorf("an actionable diagnosis lost its remediation in the one-line render: %s",
			actionable.Describe())
	}
}
