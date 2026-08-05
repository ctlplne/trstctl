// SPDX-License-Identifier: MPL-2.0

package enrollmentdiag

import (
	"errors"
	"net"
	"strings"
)

// Turning a real failure into a diagnosis (epic I4).
//
// The vocabulary next door has been complete for a while and had no callers:
// every value defined, every remediation written, and nothing in the served
// binary ever producing one. That is worth naming rather than quietly fixing,
// because a diagnosis catalogue with no classifier is the same shape of defect
// it exists to describe — a capability that looks finished from the inside.
//
// The classifier's whole job is to be conservative. A wrong diagnosis is worse
// than none: it sends an operator to the DNS zone when the responder was
// unreachable, and they lose an hour before they think to doubt the tool. So
// this matches on conditions that are unambiguous and returns CauseUnknown for
// everything else, which the catalogue already treats as a first-class answer
// rather than a fallback.

// ClassifyACME diagnoses an ACME failure from the problem type the server
// returned and the step that was running.
//
// The urn:ietf:params:acme:error:* types are a closed set defined by RFC 8555,
// which is what makes this safe to switch on: the server is telling us in a
// vocabulary it and we both agreed to, rather than in prose we would be guessing
// at.
func ClassifyACME(step Step, problemType string, err error) Diagnosis {
	switch normalizeProblem(problemType) {
	case "dns", "connection":
		// The authority could not reach or resolve the challenge. It is NOT
		// "your record is wrong": an unreachable resolver and a missing record
		// produce the same type here, and the remediation for
		// challenge_not_visible covers looking at both.
		return Diagnose(ProtocolACME, orDefault(step, StepValidation), CauseChallengeNotVisible)
	case "incorrectresponse", "unauthorized":
		if step == StepAccount || step == StepAuthorize {
			return Diagnose(ProtocolACME, step, CauseEABUnauthorized)
		}
		return Diagnose(ProtocolACME, orDefault(step, StepValidation), CauseChallengeWrongValue)
	case "ratelimited":
		return Diagnose(ProtocolACME, orDefault(step, StepOrder), CauseRateLimited)
	case "rejectedidentifier", "unsupportedidentifier":
		return Diagnose(ProtocolACME, orDefault(step, StepOrder), CauseNameNotPermitted)
	case "externalaccountrequired":
		return Diagnose(ProtocolACME, StepAccount, CauseEABUnauthorized)
	}
	// No recognised problem type. Before giving up, a transport failure is
	// unambiguous enough to name on its own.
	if isUnreachable(err) {
		return Diagnose(ProtocolACME, orDefault(step, StepOrder), CauseResponderUnreachable)
	}
	return Diagnose(ProtocolACME, orDefault(step, StepUnknownStep), CauseUnknown)
}

// ClassifyEST diagnoses an EST failure from the HTTP status and step.
//
// EST carries far less structure than ACME — the RFC 7030 surface is mostly
// status codes — so this classifies less and reaches CauseUnknown sooner. That
// asymmetry is honest: a protocol that says less about why it refused should
// produce fewer confident diagnoses, not the same number with worse evidence.
func ClassifyEST(step Step, status int, err error) Diagnosis {
	switch {
	case isUnreachable(err):
		return Diagnose(ProtocolEST, orDefault(step, StepAccount), CauseResponderUnreachable)
	case status == 401:
		// The client did not authenticate. For EST that is the TLS client
		// certificate or the HTTP credential, both of which the remediation
		// for client_cert_rejected names.
		return Diagnose(ProtocolEST, StepAccount, CauseClientCertRejected)
	case status == 403:
		// Authenticated and not permitted, which is a policy decision rather
		// than a credential problem — a different place to look.
		return Diagnose(ProtocolEST, orDefault(step, StepAuthorize), CauseTemplateACLDenied)
	case status == 429:
		return Diagnose(ProtocolEST, orDefault(step, StepOrder), CauseRateLimited)
	}
	return Diagnose(ProtocolEST, orDefault(step, StepUnknownStep), CauseUnknown)
}

// ClassifySCEP diagnoses a SCEP failure from its failInfo and step.
//
// The failInfo values are a closed set from RFC 8894, but a deliberately coarse
// one: badRequest covers most of what can go wrong. So only the values that map
// to exactly one remediation are classified.
func ClassifySCEP(step Step, failInfo string, err error) Diagnosis {
	switch strings.ToLower(strings.TrimSpace(failInfo)) {
	case "badalg", "badmessagecheck":
		// The request did not verify. For SCEP that is the challenge password
		// or the self-signed request signature.
		return Diagnose(ProtocolSCEP, orDefault(step, StepAccount), CauseClientCertRejected)
	case "badcertid":
		return Diagnose(ProtocolSCEP, orDefault(step, StepOrder), CauseNameNotPermitted)
	}
	if isUnreachable(err) {
		return Diagnose(ProtocolSCEP, orDefault(step, StepAccount), CauseResponderUnreachable)
	}
	// badRequest and badTime are deliberately NOT classified. badRequest is the
	// catch-all a SCEP server returns for most refusals, so mapping it to any
	// single cause would be inventing a diagnosis from a value that carries
	// none.
	return Diagnose(ProtocolSCEP, orDefault(step, StepUnknownStep), CauseUnknown)
}

// ClassifyADCS diagnoses an AD CS failure from the Windows error text.
//
// Text matching, which is exactly the kind of thing this package is otherwise
// careful about — so it matches only on the two stable, unambiguous phrases the
// CA emits, and returns unknown for everything else rather than pattern-matching
// its way to a guess.
func ClassifyADCS(step Step, detail string, err error) Diagnosis {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "denied by policy module") ||
		strings.Contains(lower, "0x80094800"): // CERTSRV_E_UNSUPPORTED_CERT_TYPE
		return Diagnose(ProtocolADCS, orDefault(step, StepAuthorize), CauseTemplateACLDenied)
	case strings.Contains(lower, "0x80094801") || // CERTSRV_E_NO_CERT_TYPE
		strings.Contains(lower, "no certificate template"):
		return Diagnose(ProtocolADCS, orDefault(step, StepAuthorize), CauseTemplateACLDenied)
	}
	if isUnreachable(err) {
		return Diagnose(ProtocolADCS, orDefault(step, StepAccount), CauseResponderUnreachable)
	}
	return Diagnose(ProtocolADCS, orDefault(step, StepUnknownStep), CauseUnknown)
}

// ClassifyRevocation diagnoses a revocation-reachability failure.
//
// Its own entry point because revocation fails independently of enrolment: a
// certificate can issue perfectly and still be unusable to a relying party that
// cannot check it, and the two failures send an operator to different places.
func ClassifyRevocation(err error) Diagnosis {
	if isUnreachable(err) {
		return Diagnose(ProtocolACME, StepRevocation, CauseResponderUnreachable)
	}
	return Diagnose(ProtocolACME, StepRevocation, CauseUnknown)
}

// normalizeProblem reduces an ACME problem type to its distinguishing word.
func normalizeProblem(problemType string) string {
	t := strings.ToLower(strings.TrimSpace(problemType))
	if idx := strings.LastIndex(t, ":"); idx >= 0 {
		t = t[idx+1:]
	}
	return t
}

// isUnreachable reports whether an error is a transport failure.
//
// Deliberately narrow. A timeout or a refused connection is unambiguous; an
// arbitrary error containing the word "connection" is not, and treating it as
// one would put "the responder is unreachable" in front of an operator whose
// responder is answering fine.
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// orDefault substitutes a step when the caller could not name one.
func orDefault(step, fallback Step) Step {
	if strings.TrimSpace(string(step)) == "" {
		return fallback
	}
	return step
}
