// SPDX-License-Identifier: MPL-2.0

package orchestrator

import "testing"

// TestFailedRenewalHasANonDestructiveExit is the regression guard for the
// lifecycle wedge.
//
// Both exits from renewing used to fire an external side effect: renewing →
// deployed pushes connector.deploy, renewing → revoked pushes
// revocation.publish. So an identity whose renewal FAILED had three options and
// no good one — re-deploy a certificate that was never renewed, revoke a
// perfectly valid credential, or sit in renewing forever.
//
// renewal_failed is the fourth: a recorded outcome that touches nothing outside
// the control plane, because the previous certificate is still deployed and still
// valid.
func TestFailedRenewalHasANonDestructiveExit(t *testing.T) {
	if !CanTransition(StateRenewing, StateRenewalFailed) {
		t.Fatal("a renewal cannot be recorded as failed; the only exits from renewing still " +
			"re-deploy or revoke")
	}
	if dest, ok := sideEffectFor(StateRenewing, StateRenewalFailed); ok {
		t.Errorf("recording a failed renewal fires the external side effect %q; nothing was "+
			"issued, so there is nothing to deploy", dest)
	}
	if _, ok := EventTypeFor(StateRenewing, StateRenewalFailed); !ok {
		t.Error("the transition emits no event, so a failed renewal leaves no audit record")
	}
}

// TestRenewalFailedIsNotItselfATrap is the other half. A state whose only exits
// are destructive would just move the wedge somewhere new.
func TestRenewalFailedIsNotItselfATrap(t *testing.T) {
	// Retry: re-runs the CA call, which is the point.
	if !CanTransition(StateRenewalFailed, StateRenewing) {
		t.Error("a failed renewal cannot be retried")
	}
	if dest, ok := sideEffectFor(StateRenewalFailed, StateRenewing); !ok || dest != "ca.renew" {
		t.Errorf("retrying a renewal must re-run the CA call, got %q (present=%v)", dest, ok)
	}

	// Accept: the existing certificate stands, and clearing the flag must not
	// re-push anything.
	if !CanTransition(StateRenewalFailed, StateDeployed) {
		t.Error("an operator cannot accept the current certificate and clear the failure")
	}
	if dest, ok := sideEffectFor(StateRenewalFailed, StateDeployed); ok {
		t.Errorf("clearing the failure fires %q; no new certificate exists to deploy", dest)
	}

	// Give up: still available, and still publishes revocation.
	if !CanTransition(StateRenewalFailed, StateRevoked) {
		t.Error("a failed renewal cannot be revoked")
	}
	if dest, ok := sideEffectFor(StateRenewalFailed, StateRevoked); !ok || dest != "revocation.publish" {
		t.Errorf("revoking must publish revocation, got %q (present=%v)", dest, ok)
	}
}

// TestRenewalFailedRejectsNonsenseTransitions keeps the new state as constrained
// as the others: adding a state must not quietly widen the machine.
func TestRenewalFailedRejectsNonsenseTransitions(t *testing.T) {
	for _, to := range []State{StateRequested, StateIssued, StateRetired, StateRenewalFailed} {
		if CanTransition(StateRenewalFailed, to) {
			t.Errorf("renewal_failed -> %s is permitted but is not a real lifecycle step", to)
		}
	}
	for _, from := range []State{StateRequested, StateIssued, StateDeployed, StateRevoked, StateRetired} {
		if CanTransition(from, StateRenewalFailed) {
			t.Errorf("%s -> renewal_failed is permitted; only a renewal in flight can fail", from)
		}
	}
}

// TestEveryLifecycleEventIsDistinct guards the map's shape: transitionEvents is
// keyed by edge, so two edges sharing an event name would make the audit trail
// ambiguous about which transition actually happened.
func TestEveryLifecycleEventIsDistinct(t *testing.T) {
	// identity.revoked and identity.renewing are deliberately shared across edges
	// (several states can be revoked; a renewal can start from two states), so the
	// check is that the NEW outcomes are distinguishable from a successful renewal.
	failed, _ := EventTypeFor(StateRenewing, StateRenewalFailed)
	succeeded, _ := EventTypeFor(StateRenewing, StateDeployed)
	recovered, _ := EventTypeFor(StateRenewalFailed, StateDeployed)
	if failed == succeeded {
		t.Error("a failed renewal emits the same event as a successful one; the audit trail " +
			"cannot tell them apart")
	}
	if recovered == succeeded {
		t.Error("accepting the existing certificate emits the same event as a successful renewal, " +
			"which would read as a renewal that never happened")
	}
}
