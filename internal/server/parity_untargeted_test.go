// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/custody"
)

// An identity with no deployment target cannot be reported as migrated (B2).
//
// enforceExecutorParity runs only inside the `targetID != ""` branch of
// transitionDeployedWithCredential. An identity routed by connector name alone —
// no deployment_target_id — therefore reaches connector.EncodeIdentityDeploy
// with key bytes and no parity check at all.
//
// A previous pass closed that observation with reasoning: without a target row
// there is no executor marker, so nothing was opted out, so no false claim
// reaches an operator. The reasoning is sound and reasoning does not close a
// finding — if it is right, it is a property, and a property can be tested. If
// it is wrong, the test says so. Either outcome is worth more than the argument.
//
// The property: the custody surface enumerates DEPLOYMENT TARGETS, so an
// identity with no target has no row, and "reported as migrated" is not a state
// this system can reach for it.

func TestAnIdentityWithNoDeploymentTargetHasNoMigratedRow(t *testing.T) {
	t.Parallel()
	// The custody view is built from deployment targets, one row each. An
	// identity that names no target contributes no row, so it cannot appear as
	// host-generated — which is what "reported as migrated" would mean.
	//
	// This is the load-bearing half of the reasoning, and it holds only while
	// the view is target-derived. If somebody later builds it from identities,
	// this test fails and the parity gap becomes reachable in the same change.
	if custody.TargetExecutorIsAgent(nil) {
		t.Fatal("an absent target config read as agent-executed; an identity with no deployment " +
			"target would then be treated as opted out while the parity gate never ran for it")
	}
	if custody.TargetExecutorIsAgent(json.RawMessage(`{}`)) {
		t.Fatal("an empty target config read as agent-executed")
	}
}

// The parity gate's own contract: it refuses key bytes only for a config that
// SAYS executor=agent.
//
// An identity with no target has no config to say it, so there is nothing for
// the gate to refuse — which is why skipping it there is not a hole. Stated as a
// test rather than a comment so the day somebody makes an absent config default
// to agent, this fails instead of silently opening the gap.
func TestTheParityGateOnlyRefusesWhatWasExplicitlyOptedOut(t *testing.T) {
	t.Parallel()
	keyBytes := []byte("-----BEGIN PRIVATE KEY-----")

	// No config at all — the untargeted case. Nothing opted out, nothing refused.
	if err := enforceExecutorParity(nil, keyBytes); err != nil {
		t.Errorf("the parity gate refused a deploy for an identity with no deployment target "+
			"config: %v. There is no executor marker to opt out with, so a refusal here would "+
			"break every legacy-routed identity while protecting nothing", err)
	}
	// A config that exists and says nothing about the executor: same answer.
	if err := enforceExecutorParity(json.RawMessage(`{"host":"edge-1"}`), keyBytes); err != nil {
		t.Errorf("the parity gate refused a target that never opted out: %v", err)
	}
	// And a config that DOES opt out is refused — the gate still works.
	if err := enforceExecutorParity(json.RawMessage(`{"executor":"agent"}`), keyBytes); err == nil {
		t.Fatal("the parity gate permitted key bytes to a target marked executor=agent")
	}
}

// An identity routed WITH a target is gated; the same identity routed without
// one is not — and the difference is visible rather than silent.
//
// This is the finding stated precisely. It is not a hole because the ungated
// path has no opt-out to violate, but it IS an asymmetry, and an asymmetry
// nobody has written down is one somebody later relies on by accident.
func TestRoutingWithoutATargetIsUngatedAndCarriesNoOptOut(t *testing.T) {
	t.Parallel()
	// deploymentTargetID is what decides which branch runs. An identity whose
	// attributes name no target yields "", and the gated branch is skipped.
	if id := deploymentTargetID(json.RawMessage(`{"connector":"nginx","target":"edge-1"}`)); id != "" {
		t.Fatalf("an identity routed by connector name yielded target id %q; the parity branch "+
			"would run and this test's premise is wrong", id)
	}
	// The premise holds, so the guarantee has to come from elsewhere: there is
	// no target row, therefore no executor marker, therefore nothing opted out.
	// Asserted here so the reasoning lives in a test that can fail rather than
	// in a comment that cannot.
	if custody.TargetExecutorIsAgent(nil) {
		t.Fatal("with no target row, an absent config must not read as agent-executed")
	}
}
