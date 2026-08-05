// SPDX-License-Identifier: MPL-2.0

// Package issuancerequest holds the lifecycle of a first-class issuance request
// (epic I3).
//
// The lifecycle lives here, as pure functions over strings, rather than in the
// store or the handler, because the interesting property is which transitions
// are ILLEGAL — and a rule enforced only by whichever handler happens to run is
// a rule that holds until somebody adds a second handler.
package issuancerequest

import "fmt"

// The states a request can be in.
//
// Approved and Issued are separate on purpose. Approval is a DECISION; issuance
// is an OUTCOME. Collapsing them would make a request whose issuance later
// failed — a signer outage, a policy refusal at mint time — look successfully
// fulfilled, and the requester would go looking for a certificate that does not
// exist.
const (
	StateRequested = "requested"
	StateApproved  = "approved"
	StateDenied    = "denied"
	StateExpired   = "expired"
	StateCancelled = "cancelled"
	StateIssued    = "issued"
)

// States is every legal state, in lifecycle order. Exported so the API, the
// console filter, and the OpenAPI enum all read from one list instead of three
// hand-copied ones that drift.
var States = []string{StateRequested, StateApproved, StateDenied, StateExpired, StateCancelled, StateIssued}

// Terminal reports whether a state accepts no further transitions.
//
// Approved is NOT terminal: the request still has to be issued, and treating it
// as finished is how an approved-but-never-minted request disappears from
// everyone's queue.
func Terminal(state string) bool {
	switch state {
	case StateDenied, StateExpired, StateCancelled, StateIssued:
		return true
	default:
		return false
	}
}

// legal maps each state to the states it may move to.
var legal = map[string][]string{
	StateRequested: {StateApproved, StateDenied, StateExpired, StateCancelled},
	// An approved request can still be cancelled by its requester (they no
	// longer need it) and can still expire (nobody minted it in time). It can
	// NOT go back to requested: re-opening a decided request would let an
	// approval be silently reused for a different ask.
	StateApproved: {StateIssued, StateCancelled, StateExpired},
}

// Transition validates a state change and returns the new state.
//
// It refuses every transition out of a terminal state. That is the rule worth
// enforcing centrally: without it, a denied request could be approved by a
// second reviewer who did not notice, and the audit trail would show both.
func Transition(from, to string) (string, error) {
	if from == to {
		return "", fmt.Errorf("issuancerequest: request is already %s", from)
	}
	if Terminal(from) {
		return "", fmt.Errorf(
			"issuancerequest: %s is final and cannot become %s; re-deciding a closed request would "+
				"let a second reviewer overturn the first without either of them knowing", from, to)
	}
	for _, allowed := range legal[from] {
		if allowed == to {
			return to, nil
		}
	}
	return "", fmt.Errorf("issuancerequest: %s cannot become %s", from, to)
}

// CanDecide reports whether a principal may approve or deny.
//
// Separation of duties: the requester is never their own approver. This is the
// same rule the dual-control gate applies to issuance, and a request lifecycle
// that did not enforce it would be a way around that gate — ask, approve
// yourself, and the certificate is minted with an approval record that looks
// legitimate.
func CanDecide(requester, principal string) error {
	if requester == "" || principal == "" {
		return fmt.Errorf("issuancerequest: both requester and approver must be known")
	}
	if requester == principal {
		return fmt.Errorf(
			"issuancerequest: %s opened this request and cannot decide it; self-approval would make "+
				"the approval record look legitimate while nobody independent ever looked", principal)
	}
	return nil
}
