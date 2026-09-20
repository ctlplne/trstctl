// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"testing"

	"trstctl.com/trstctl/internal/agentid/taskenv"
)

// vectors_test.go exercises the CONFORMANCE-VECTOR RUNNER (vectors.go) against a
// small SELF-GENERATED vector set spanning accept + every fail-closed refusal. It
// is the same runner AGID-12's published canonical vectors will drop into, so a
// green run here means the runner + vector shape are ready for the published set.
// Every vector is fully materialized and OFFLINE.

// buildSelfVectors builds a representative set of offline vectors: a valid accept
// (signed-token), an out-of-policy agent stack, an over-authority action, an
// out-of-task-scope action, a tool absent from the manifest, and an expired
// credential. Each pins the expected fail-closed reason via ExpectErr.
func buildSelfVectors(t *testing.T) []Vector {
	t.Helper()
	tools := []string{"read-object", "list-bucket"}
	repr := buildRepr(t, "vector-prompt", tools)
	other := buildRepr(t, "rogue-prompt", tools)
	class, op := "reader", "read-object"

	credAccept, rootAccept := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	credOutPolicy, rootOutPolicy := tokenCred(t, fullBinding(other, class, nil), testNow-60, testNow+60)
	credOverAuth, rootOverAuth := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	credAbsentTool, rootAbsentTool := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	credExpired, rootExpired := tokenCred(t, fullBinding(repr, class, nil), testNow-120, testNow-60)

	// Task-scope vector: authority grants delete, task envelope authorizes only read.
	env := buildTaskEnvelope(t, []taskenv.Commitment{{Name: "op:read-object", Digest: []byte("x")}})
	envDig, err := env.Digest()
	if err != nil {
		t.Fatalf("env digest: %v", err)
	}
	credOutTask, rootOutTask := tokenCred(t, fullBinding(repr, class, envDig), testNow-60, testNow+60)
	taskPolicy := approvePolicy(repr, class, op, tools).GrantOperations(class, "delete-object")
	taskPolicy.ExpectedTaskEnvelope = &env

	basePolicy := approvePolicy(repr, class, op, tools)

	return []Vector{
		{
			Name:       "accept-valid-token",
			Credential: credAccept, TrustRoot: rootAccept, Policy: basePolicy,
			Action: Action{Operation: op, Tool: "read-object"}, UnixNow: testNow, Expect: Accept,
		},
		{
			Name:       "refuse-out-of-policy-agent-stack",
			Credential: credOutPolicy, TrustRoot: rootOutPolicy, Policy: basePolicy,
			Action: Action{Operation: op, Tool: "read-object"}, UnixNow: testNow,
			Expect: Refuse, ExpectErr: ErrAgentStackNotApproved,
		},
		{
			Name:       "refuse-action-exceeds-authority",
			Credential: credOverAuth, TrustRoot: rootOverAuth, Policy: basePolicy,
			Action: Action{Operation: "delete-object", Tool: "read-object"}, UnixNow: testNow,
			Expect: Refuse, ExpectErr: ErrActionExceedsAuthority,
		},
		{
			Name:       "refuse-action-outside-task-scope",
			Credential: credOutTask, TrustRoot: rootOutTask, Policy: taskPolicy,
			Action: Action{Operation: "delete-object", Tool: "read-object"}, UnixNow: testNow,
			Expect: Refuse, ExpectErr: ErrActionOutsideTaskScope,
		},
		{
			Name:       "refuse-tool-absent-from-manifest",
			Credential: credAbsentTool, TrustRoot: rootAbsentTool, Policy: basePolicy,
			Action: Action{Operation: op, Tool: "spawn-shell"}, UnixNow: testNow,
			Expect: Refuse, ExpectErr: ErrToolAbsentFromManifest,
		},
		{
			Name:       "refuse-expired-credential",
			Credential: credExpired, TrustRoot: rootExpired, Policy: basePolicy,
			Action: Action{Operation: op, Tool: "read-object"}, UnixNow: testNow,
			Expect: Refuse, ExpectErr: ErrCredentialExpired,
		},
	}
}

// TestConformanceVectorRunner_SelfVectors runs the self-generated vectors through
// the runner and asserts ALL pass (each accept accepts; each refuse refuses with
// the pinned reason).
func TestConformanceVectorRunner_SelfVectors(t *testing.T) {
	vectors := buildSelfVectors(t)
	results, allPassed := RunVectors(vectors)
	for _, r := range results {
		if !r.Passed {
			t.Errorf("vector %q FAILED: %s (err=%v)", r.Name, r.Detail, r.Err)
		} else {
			t.Logf("vector %q ok", r.Name)
		}
	}
	if !allPassed {
		t.Fatal("not all conformance vectors passed")
	}
	if len(results) != len(vectors) {
		t.Fatalf("runner returned %d results for %d vectors", len(results), len(vectors))
	}
}

// TestConformanceVectorRunner_DetectsWrongExpectation proves the runner is not
// vacuous: a vector whose EXPECTED outcome is wrong (expects accept for a
// credential that must refuse) is reported as a FAILURE, so the runner would catch
// a non-conformant implementation rather than rubber-stamp it.
func TestConformanceVectorRunner_DetectsWrongExpectation(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "vector-prompt", tools)
	class, op := "reader", "read-object"
	// A credential that will REFUSE (expired), but the vector wrongly expects Accept.
	credExpired, rootExpired := tokenCred(t, fullBinding(repr, class, nil), testNow-120, testNow-60)
	bad := Vector{
		Name:       "wrongly-expects-accept",
		Credential: credExpired, TrustRoot: rootExpired,
		Policy: approvePolicy(repr, class, op, tools),
		Action: Action{Operation: op, Tool: "read-object"}, UnixNow: testNow, Expect: Accept,
	}
	r := RunVector(bad)
	if r.Passed {
		t.Fatal("runner passed a vector with a wrong expectation; it must fail (not vacuous)")
	}

	// And a vector expecting the WRONG refusal reason is also caught.
	badReason := Vector{
		Name:       "wrong-refusal-reason",
		Credential: credExpired, TrustRoot: rootExpired,
		Policy: approvePolicy(repr, class, op, tools),
		Action: Action{Operation: op, Tool: "read-object"}, UnixNow: testNow,
		Expect: Refuse, ExpectErr: ErrToolAbsentFromManifest, // actual reason is ErrCredentialExpired
	}
	if RunVector(badReason).Passed {
		t.Fatal("runner passed a vector pinning the wrong refusal reason; it must fail")
	}
}
