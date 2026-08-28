// SPDX-License-Identifier: MPL-2.0

package enrollmentdiag_test

import (
	"errors"
	"net"
	"testing"

	"trstctl.com/trstctl/internal/enrollmentdiag"
)

// A wrong diagnosis is worse than none (epic I4).
//
// This is the whole design constraint. A tool that says "your DNS record is
// missing" when the responder was unreachable sends an operator to the zone file
// for an hour before they think to doubt it — and they will doubt the tool
// afterwards, on the occasions it was right.
//
// So the tests that matter most are the ones asserting the classifier DECLINES.

func TestACMEProblemTypesMapToTheirActualCause(t *testing.T) {
	t.Parallel()
	cases := []struct {
		problem string
		step    enrollmentdiag.Step
		want    enrollmentdiag.Cause
	}{
		{"urn:ietf:params:acme:error:dns", enrollmentdiag.StepValidation, enrollmentdiag.CauseChallengeNotVisible},
		{"urn:ietf:params:acme:error:connection", enrollmentdiag.StepValidation, enrollmentdiag.CauseChallengeNotVisible},
		{"urn:ietf:params:acme:error:incorrectResponse", enrollmentdiag.StepValidation, enrollmentdiag.CauseChallengeWrongValue},
		{"urn:ietf:params:acme:error:rateLimited", enrollmentdiag.StepOrder, enrollmentdiag.CauseRateLimited},
		{"urn:ietf:params:acme:error:rejectedIdentifier", enrollmentdiag.StepOrder, enrollmentdiag.CauseNameNotPermitted},
		{"urn:ietf:params:acme:error:externalAccountRequired", enrollmentdiag.StepAccount, enrollmentdiag.CauseEABUnauthorized},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.problem, func(t *testing.T) {
			t.Parallel()
			d := enrollmentdiag.ClassifyACME(tc.step, tc.problem, nil)
			if d.Cause != tc.want {
				t.Errorf("cause = %q, want %q", d.Cause, tc.want)
			}
			if d.Remediation == "" {
				t.Error("a classified failure carries no remediation, so it names nothing to do")
			}
		})
	}
}

// A DNS problem must NOT be reported as a wrong challenge value.
//
// The two look similar and send an operator to opposite places: one is "your
// resolver or record is not visible from the authority", the other is "the
// record is there and says the wrong thing". Conflating them is the specific
// mistake this classifier is careful about.
func TestAnUnreachableChallengeIsNotReportedAsAWrongValue(t *testing.T) {
	t.Parallel()
	d := enrollmentdiag.ClassifyACME(enrollmentdiag.StepValidation,
		"urn:ietf:params:acme:error:dns", nil)
	if d.Cause == enrollmentdiag.CauseChallengeWrongValue {
		t.Fatal("a DNS-visibility failure was diagnosed as a wrong challenge value; the operator " +
			"would go and edit a record that is already correct")
	}
	if d.Cause != enrollmentdiag.CauseChallengeNotVisible {
		t.Errorf("cause = %q, want challenge_not_visible", d.Cause)
	}
}

// An unrecognised problem type produces "unknown", not a guess.
func TestAnUnrecognisedFailureIsNotGuessedAt(t *testing.T) {
	t.Parallel()
	for _, problem := range []string{
		"urn:ietf:params:acme:error:serverInternal",
		"urn:ietf:params:acme:error:malformed",
		"something-else-entirely",
		"",
	} {
		d := enrollmentdiag.ClassifyACME(enrollmentdiag.StepOrder, problem, nil)
		if d.Cause != enrollmentdiag.CauseUnknown {
			t.Errorf("problem %q was diagnosed as %q; a cause the classifier cannot establish "+
				"must read as unknown rather than as the nearest-looking one", problem, d.Cause)
		}
		if d.Remediation != "" {
			t.Errorf("an unknown cause carried remediation %q; inventing an action is the whole "+
				"failure mode this package exists to avoid", d.Remediation)
		}
	}
}

// A transport failure is named even when the protocol said nothing.
func TestATransportFailureIsRecognisedWithoutAProblemType(t *testing.T) {
	t.Parallel()
	unreachable := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	d := enrollmentdiag.ClassifyACME(enrollmentdiag.StepOrder, "", unreachable)
	if d.Cause != enrollmentdiag.CauseResponderUnreachable {
		t.Errorf("cause = %q, want responder_unreachable", d.Cause)
	}
}

// An arbitrary error is NOT a transport failure.
//
// The unreachable check is narrow on purpose: an error that merely mentions a
// connection is not evidence of one failing, and treating it as such would put
// "the responder is unreachable" in front of an operator whose responder is
// answering perfectly.
func TestAnArbitraryErrorIsNotCalledUnreachable(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		errors.New("connection to the policy engine returned a denial"),
		errors.New("network policy refused this template"),
		errors.New("timeout parsing configuration"),
	} {
		d := enrollmentdiag.ClassifyACME(enrollmentdiag.StepOrder, "", err)
		if d.Cause == enrollmentdiag.CauseResponderUnreachable {
			t.Errorf("error %q was diagnosed as an unreachable responder on the strength of its "+
				"wording", err)
		}
	}
}

// EST distinguishes "you did not authenticate" from "you are not permitted".
//
// 401 and 403 send an operator to different places — a credential versus a
// policy — and an EST server that says one must not be reported as the other.
func TestESTSeparatesAuthenticationFromAuthorization(t *testing.T) {
	t.Parallel()
	unauthenticated := enrollmentdiag.ClassifyEST(enrollmentdiag.StepAccount, 401, nil)
	if unauthenticated.Cause != enrollmentdiag.CauseClientCertRejected {
		t.Errorf("401 = %q, want client_cert_rejected", unauthenticated.Cause)
	}
	forbidden := enrollmentdiag.ClassifyEST(enrollmentdiag.StepAuthorize, 403, nil)
	if forbidden.Cause != enrollmentdiag.CauseTemplateACLDenied {
		t.Errorf("403 = %q, want template_acl_denied", forbidden.Cause)
	}
	if unauthenticated.Cause == forbidden.Cause {
		t.Error("EST 401 and 403 produced the same diagnosis; they are a credential problem and " +
			"a policy problem, and an operator fixes them in different systems")
	}
}

// SCEP's catch-all failInfo is deliberately not classified.
func TestSCEPBadRequestIsNotMappedToAGuess(t *testing.T) {
	t.Parallel()
	d := enrollmentdiag.ClassifySCEP(enrollmentdiag.StepIssue, "badRequest", nil)
	if d.Cause != enrollmentdiag.CauseUnknown {
		t.Errorf("SCEP badRequest was diagnosed as %q. It is the value a SCEP server returns for "+
			"most refusals, so mapping it to any single cause invents a diagnosis from a value "+
			"that carries none", d.Cause)
	}
}

// CMP uses handler-owned reason codes, not text matching. These four branches
// are the cases where the server has enough evidence to name a repair safely.
func TestCMPClosedReasonsMapToDistinctRepairs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		step   enrollmentdiag.Step
		reason enrollmentdiag.CMPReason
		want   enrollmentdiag.Cause
	}{
		{"protection", enrollmentdiag.StepAccount, enrollmentdiag.CMPReasonProtectionRejected, enrollmentdiag.CauseClientCertRejected},
		{"identity", enrollmentdiag.StepAuthorize, enrollmentdiag.CMPReasonIdentityMismatch, enrollmentdiag.CauseNameNotPermitted},
		{"capacity", enrollmentdiag.StepIssue, enrollmentdiag.CMPReasonCapacityRejected, enrollmentdiag.CauseCapacityFull},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			diagnosis := enrollmentdiag.ClassifyCMP(tc.step, tc.reason, nil)
			if diagnosis.Protocol != enrollmentdiag.ProtocolCMP || diagnosis.Cause != tc.want {
				t.Fatalf("CMP diagnosis = %+v, want protocol cmp and cause %q", diagnosis, tc.want)
			}
			if !diagnosis.Actionable() {
				t.Fatal("a closed CMP reason did not produce an actionable repair")
			}
		})
	}
}

func TestCMPDoesNotGuessFromUnknownReasonsOrErrorProse(t *testing.T) {
	t.Parallel()
	for _, reason := range []enrollmentdiag.CMPReason{enrollmentdiag.CMPReasonUnknown, "new-server-reason", ""} {
		diagnosis := enrollmentdiag.ClassifyCMP(enrollmentdiag.StepIssue, reason,
			errors.New("policy denied because client certificate rate limit text appeared"))
		if diagnosis.Cause != enrollmentdiag.CauseUnknown || diagnosis.Remediation != "" {
			t.Fatalf("unknown CMP reason %q was guessed as %+v", reason, diagnosis)
		}
	}
}

// AD CS matches only its stable, unambiguous error phrases.
func TestADCSMatchesOnlyItsUnambiguousErrors(t *testing.T) {
	t.Parallel()
	denied := enrollmentdiag.ClassifyADCS(enrollmentdiag.StepAuthorize,
		"Denied by Policy Module 0x80094800", nil)
	if denied.Cause != enrollmentdiag.CauseTemplateACLDenied {
		t.Errorf("a policy-module denial = %q, want template_acl_denied", denied.Cause)
	}
	vague := enrollmentdiag.ClassifyADCS(enrollmentdiag.StepIssue,
		"The request failed for an unspecified reason", nil)
	if vague.Cause != enrollmentdiag.CauseUnknown {
		t.Errorf("a vague AD CS error was diagnosed as %q rather than unknown", vague.Cause)
	}
}

// Every classified diagnosis carries something to do; unknown carries nothing.
func TestActionableDiagnosesNameAnActionAndUnknownDoesNot(t *testing.T) {
	t.Parallel()
	classified := enrollmentdiag.ClassifyEST(enrollmentdiag.StepAuthorize, 403, nil)
	if !classified.Actionable() {
		t.Error("a classified diagnosis is not actionable")
	}
	unknown := enrollmentdiag.ClassifySCEP(enrollmentdiag.StepIssue, "badRequest", nil)
	if unknown.Actionable() {
		t.Error("an unknown cause reported itself as actionable; it names nothing to do")
	}
}
