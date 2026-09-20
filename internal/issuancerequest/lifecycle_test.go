// SPDX-License-Identifier: BUSL-1.1

package issuancerequest

import (
	"strings"
	"testing"
)

// A closed request must stay closed.
//
// Without this, a denied request can be approved by a second reviewer who did
// not notice the denial, and the audit trail shows both decisions with nothing
// saying which one governs.
func TestATerminalRequestCannotBeReDecided(t *testing.T) {
	t.Parallel()
	for _, from := range []string{StateDenied, StateExpired, StateCancelled, StateIssued} {
		for _, to := range []string{StateApproved, StateDenied, StateRequested, StateIssued} {
			if from == to {
				continue
			}
			_, err := Transition(from, to)
			if err == nil {
				t.Fatalf("%s -> %s was allowed. A closed request that can be re-decided lets a "+
					"second reviewer overturn the first without either of them knowing", from, to)
			}
			// Assert on WHY. Terminal states also happen to have no entry in the
			// legal map, so a plain "it errored" assertion passes even if the
			// terminal guard is removed — it would be proving the map is empty,
			// not that closed means closed. The realistic future mistake is
			// somebody adding a transition out of denied; only this guard stops
			// that, so this is what has to be pinned.
			if !strings.Contains(err.Error(), "is final") {
				t.Errorf("%s -> %s was refused for the wrong reason (%v). It must be refused "+
					"BECAUSE the state is final, so adding a legal transition out of it later "+
					"cannot silently reopen it", from, to, err)
			}
		}
	}
}

// Approved is deliberately NOT terminal.
func TestApprovedIsNotTerminalBecauseIssuanceStillHasToHappen(t *testing.T) {
	t.Parallel()
	if Terminal(StateApproved) {
		t.Fatal("approved is treated as final. An approved request that was never minted would " +
			"drop out of every queue, and the requester would wait for a certificate nobody is " +
			"still working on")
	}
	if _, err := Transition(StateApproved, StateIssued); err != nil {
		t.Fatalf("approved -> issued refused: %v", err)
	}
	// It must still be able to expire and be cancelled.
	for _, to := range []string{StateExpired, StateCancelled} {
		if _, err := Transition(StateApproved, to); err != nil {
			t.Errorf("approved -> %s refused: %v", to, err)
		}
	}
	// But never back to requested.
	if _, err := Transition(StateApproved, StateRequested); err == nil {
		t.Fatal("approved -> requested was allowed; re-opening a decided request lets an approval " +
			"be silently reused for a different ask")
	}
}

// Issuance is an outcome, not a decision. If these were one state, a request
// whose mint FAILED would read as fulfilled.
func TestApprovalAndIssuanceAreDistinctStates(t *testing.T) {
	t.Parallel()
	if StateApproved == StateIssued {
		t.Fatal("approved and issued are the same state; a request whose issuance failed would " +
			"look successfully fulfilled and nobody would go looking for the missing certificate")
	}
}

// Separation of duties. A request lifecycle that let a requester approve
// themselves would be a way around the dual-control issuance gate.
func TestARequesterCannotApproveTheirOwnRequest(t *testing.T) {
	t.Parallel()
	err := CanDecide("alice@example.com", "alice@example.com")
	if err == nil {
		t.Fatal("a requester approved their own request.\n\n" +
			"That is a bypass of dual control that leaves an approval record looking legitimate: " +
			"the row says somebody approved it, and that somebody is the person who asked.")
	}
	if !strings.Contains(err.Error(), "cannot decide") {
		t.Errorf("error does not say why: %v", err)
	}
	if err := CanDecide("alice@example.com", "bob@example.com"); err != nil {
		t.Fatalf("an independent approver was refused: %v", err)
	}
	// An unknown principal on either side must fail closed, not pass because
	// two empty strings happen to differ from nothing.
	if err := CanDecide("", ""); err == nil {
		t.Fatal("two unknown principals were accepted; an approval by nobody is not an approval")
	}
}

// The state list is one list. Three hand-copied enums — API, console filter,
// OpenAPI — drift, and the one that drifts silently accepts a state the others
// reject.
func TestEveryStateIsReachableFromTheExportedList(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, s := range States {
		seen[s] = true
	}
	for _, s := range []string{StateRequested, StateApproved, StateDenied, StateExpired, StateCancelled, StateIssued} {
		if !seen[s] {
			t.Errorf("state %q is not in States; a filter built from that list would silently omit it", s)
		}
	}
	if len(States) != 6 {
		t.Fatalf("States has %d entries, want 6", len(States))
	}
}

// Every non-terminal state must have somewhere to go, or a request can wedge.
func TestNoRequestCanWedgeInANonTerminalState(t *testing.T) {
	t.Parallel()
	for _, s := range States {
		if Terminal(s) {
			continue
		}
		if len(legal[s]) == 0 {
			t.Fatalf("%q is non-terminal but has no legal transition; a request in it would sit in "+
				"the queue forever with no way out", s)
		}
	}
}
