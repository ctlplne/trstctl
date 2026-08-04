// SPDX-License-Identifier: MPL-2.0

// Package enrollmentdiag turns a failed enrollment into a specific step, a
// specific cause, and something to do about it (epic I4).
//
// `trstctl doctor` diagnoses the control plane's own health. It has never
// diagnosed the customer's PKI failures, which are the ones people actually hit:
// an ACME order that fails validation, an EST request refused by a template ACL,
// a SCEP challenge the CA rejects. What those produced was a protocol error
// string — accurate, and useless to the person holding it.
//
// The gap is not information, it is LOCATION. "urn:ietf:params:acme:error:unauthorized"
// tells you the CA said no; it does not tell you the TXT record never became
// visible from the CA's resolver, which is the actual thing to go and fix. A
// diagnosis is a step plus a cause plus a next action, and a system that has the
// first two and withholds the third has produced a log line, not a diagnosis.
//
// The design constraint worth stating: the cause set is CLOSED, and there is an
// explicit unknown in it. A diagnostic that guesses is worse than one that says
// it does not know — an operator sent to check DNS because the system pattern-
// matched an error string will spend an hour there before doubting it, and the
// hour is the cost of a confident wrong answer.
package enrollmentdiag

import (
	"fmt"
	"sort"
	"strings"
)

// Protocol names the enrollment surface a trace belongs to.
type Protocol string

const (
	ProtocolACME Protocol = "acme"
	ProtocolEST  Protocol = "est"
	ProtocolSCEP Protocol = "scep"
	ProtocolADCS Protocol = "adcs"
)

// Step is where in an enrollment the failure happened.
//
// Ordered within a protocol, because "which step" is only meaningful relative to
// the ones that succeeded: a failure at validation means account and order both
// worked, and that narrows the search more than the failure itself does.
type Step string

const (
	StepAccount     Step = "account"     // ACME account / EST or SCEP client auth
	StepOrder       Step = "order"       // order or request creation
	StepChallenge   Step = "challenge"   // challenge provisioning
	StepValidation  Step = "validation"  // the authority checking the challenge
	StepAuthorize   Step = "authorize"   // template ACL / EAB / policy authorization
	StepIssue       Step = "issue"       // signing
	StepChainBuild  Step = "chain_build" // assembling the served chain
	StepRevocation  Step = "revocation"  // CRL/OCSP reachability
	StepUnknownStep Step = "unknown"     // the failure could not be placed
)

// Cause is the closed set of diagnoses.
//
// Closed on purpose. Every value here has a remediation somebody can act on; a
// free-text cause would let the system emit prose that reads like a diagnosis
// and names nothing to do.
type Cause string

const (
	CauseChallengeNotVisible  Cause = "challenge_not_visible"
	CauseChallengeWrongValue  Cause = "challenge_wrong_value"
	CauseTemplateACLDenied    Cause = "template_acl_denied"
	CauseEABUnauthorized      Cause = "eab_unauthorized"
	CauseClientCertRejected   Cause = "client_cert_rejected"
	CauseResponderUnreachable Cause = "responder_unreachable"
	CauseChainIncomplete      Cause = "chain_incomplete"
	CauseNameNotPermitted     Cause = "name_not_permitted"
	CauseRateLimited          Cause = "rate_limited"
	// CauseUnknown is a first-class value, not a fallback nobody meant. A
	// diagnostic that guesses costs an operator an hour in the wrong place
	// before they think to doubt it, so "we could not place this" is a better
	// answer than a confident wrong one.
	CauseUnknown Cause = "unknown"
)

// Diagnosis is one plain-language explanation with an action.
type Diagnosis struct {
	Protocol Protocol `json:"protocol"`
	Step     Step     `json:"step"`
	Cause    Cause    `json:"cause"`
	// Summary is what happened, in the operator's terms rather than the
	// protocol's.
	Summary string `json:"summary"`
	// Remediation is what to do. Empty only for CauseUnknown, where inventing
	// one would be the whole failure mode this package exists to avoid.
	Remediation string `json:"remediation,omitempty"`
	// ProveFixedRef points at the verification that would demonstrate the fix
	// actually took — D2's handshake evidence rather than a second enrollment
	// attempt, because a successful retry proves issuance worked and says
	// nothing about whether the endpoint serves it.
	ProveFixedRef string `json:"prove_fixed_ref,omitempty"`
}

// catalog is the single table mapping a cause to its words.
//
// One table rather than a switch at each call site: the remediation text is the
// product here, and text that lives in three places diverges in two of them.
var catalog = map[Cause]struct{ summary, remediation string }{
	CauseChallengeNotVisible: {
		"The authority could not see the challenge this system published.",
		"The record was written but the authority's resolver did not return it. Check propagation " +
			"from an external resolver rather than an internal one — a split-horizon DNS view is " +
			"the usual cause, and it looks correct from inside.",
	},
	CauseChallengeWrongValue: {
		"The authority saw a challenge value that did not match the one expected.",
		"A stale record from a previous attempt is usually still present. Remove the old value " +
			"rather than adding the new one alongside it.",
	},
	CauseTemplateACLDenied: {
		"The authority refused the request under its certificate template's access control.",
		"The enrolling account needs Enroll permission on that template. This is set on the " +
			"template in the CA, not in trstctl, and a template that works for one account " +
			"routinely refuses another.",
	},
	CauseEABUnauthorized: {
		"External Account Binding was rejected, so the account was never authorized.",
		"The EAB key id or HMAC does not match what the authority holds, or the binding has " +
			"already been consumed. Issue a fresh binding rather than reusing one.",
	},
	CauseClientCertRejected: {
		"The client certificate presented for enrollment was refused.",
		"Check that it chains to a root the authority trusts and has not expired. An enrollment " +
			"certificate that worked last month is a common expiry surprise.",
	},
	CauseResponderUnreachable: {
		"The revocation responder could not be reached from this vantage.",
		"Reachability is per-vantage: a responder visible to the control plane may be blocked from " +
			"the segment that actually needs it. Probe from the relay in that segment before " +
			"concluding the responder is down.",
	},
	CauseChainIncomplete: {
		"The served chain is missing an intermediate, so some clients cannot build a path.",
		"Clients that already cache the intermediate will succeed and hide this. Test with a " +
			"cold trust store, not a machine that has connected before.",
	},
	CauseNameNotPermitted: {
		"The requested name is outside what this authority or profile permits.",
		"Check the profile's permitted DNS suffixes and the issuing CA's name constraints. A name " +
			"that used to work may have been narrowed by a constraint added upstream.",
	},
	CauseRateLimited: {
		"The authority rate-limited this request.",
		"Back off rather than retrying — a retry loop against a rate limit extends the window. " +
			"Public CAs count failures as well as successes.",
	},
	CauseUnknown: {
		"This failure could not be placed at a specific step.",
		// Deliberately empty. See CauseUnknown.
		"",
	},
}

// Diagnose builds a diagnosis for a known protocol, step and cause.
func Diagnose(p Protocol, step Step, cause Cause) Diagnosis {
	entry, known := catalog[cause]
	if !known {
		// An unrecognized cause is reported AS unknown rather than passed
		// through, so a caller cannot smuggle free text into a closed set.
		entry = catalog[CauseUnknown]
		cause = CauseUnknown
		step = StepUnknownStep
	}
	return Diagnosis{
		Protocol: p, Step: step, Cause: cause,
		Summary: entry.summary, Remediation: entry.remediation,
	}
}

// WithProveFixed attaches the verification reference that would demonstrate the
// fix landed.
func (d Diagnosis) WithProveFixed(ref string) Diagnosis {
	d.ProveFixedRef = strings.TrimSpace(ref)
	return d
}

// Actionable reports whether this diagnosis tells the reader what to do.
//
// Used by the console to separate rows worth acting on from rows that only say
// something went wrong. The distinction is the entire point of the package, so
// it is a method rather than a check callers each write differently.
func (d Diagnosis) Actionable() bool {
	return d.Cause != CauseUnknown && strings.TrimSpace(d.Remediation) != ""
}

// Causes lists the closed set, for the console's filter and for the guard test
// that every cause has words.
func Causes() []Cause {
	out := make([]Cause, 0, len(catalog))
	for c := range catalog {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Describe renders a diagnosis as one line for a support bundle.
func (d Diagnosis) Describe() string {
	if !d.Actionable() {
		return fmt.Sprintf("%s/%s: %s", d.Protocol, d.Step, d.Summary)
	}
	return fmt.Sprintf("%s/%s (%s): %s — %s", d.Protocol, d.Step, d.Cause, d.Summary, d.Remediation)
}
