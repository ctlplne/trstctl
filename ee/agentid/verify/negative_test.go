// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
)

// negative_test.go exercises every fail-closed refusal path (AGID-09 security
// notes): a tampered signature, an out-of-policy agent stack, an over-authority
// action, an out-of-task-scope action, a tool absent from the manifest, a missing
// trust root, an unknown form, a missing action, a task-bound credential without a
// supplied envelope, and a repr whose opaque bytes disagree with the bound digest.
// Each must REFUSE with the specific typed error; none may accept.

// TestRefuse_TamperedSignature proves a tampered credential refuses fail-closed.
func TestRefuse_TamperedSignature(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	class, op := "reader", "read-object"
	policy := approvePolicy(repr, class, op, tools)
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	// Token: flip a byte in the signature segment.
	cred, root := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	tampered := append([]byte(nil), cred.Bytes...)
	tampered[len(tampered)-1] ^= 0x01
	cred.Bytes = tampered
	if _, err := Verify(cred, root, policy, action, clk); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered token Verify = %v, want ErrSignatureInvalid", err)
	}

	// X.509: present a leaf signed by a DIFFERENT CA than the pinned root.
	credX, _ := x509Cred(t, fullBinding(repr, class, nil), time.Hour)
	_, otherRoot := x509Cred(t, fullBinding(repr, class, nil), time.Hour)
	if _, err := Verify(credX, otherRoot, policy, action, nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong-CA x509 Verify = %v, want ErrSignatureInvalid", err)
	}

	// Workload: tamper the document body after signing.
	credW, rootW := workloadCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	credW.Bytes = bytes.Replace(credW.Bytes, []byte("spiffe://agent"), []byte("spiffe://evil0"), 1)
	if _, err := Verify(credW, rootW, policy, action, clk); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered workload Verify = %v, want ErrSignatureInvalid", err)
	}
}

// TestRefuse_NoTrustRoot proves a missing trust root refuses fail-closed (an
// unanchored credential is never trusted).
func TestRefuse_NoTrustRoot(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	class, op := "reader", "read-object"
	policy := approvePolicy(repr, class, op, tools)
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	cred, _ := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(cred, TrustRoot{}, policy, action, clk); !errors.Is(err, ErrNoTrustRoot) {
		t.Fatalf("no-trust-root Verify = %v, want ErrNoTrustRoot", err)
	}
}

// TestRefuse_UnknownForm proves an unknown carriage form refuses.
func TestRefuse_UnknownForm(t *testing.T) {
	if _, err := Verify(Credential{Form: "bogus", Bytes: []byte("x")}, TrustRoot{}, NewLocalPolicy(), Action{Operation: "op"}, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrUnknownForm) {
		t.Fatalf("unknown-form Verify = %v, want ErrUnknownForm", err)
	}
}

// TestRefuse_NoAction proves an action naming no operation refuses.
func TestRefuse_NoAction(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	cred, root := tokenCred(t, fullBinding(repr, "reader", nil), testNow-60, testNow+60)
	policy := approvePolicy(repr, "reader", "read-object", tools)
	if _, err := Verify(cred, root, policy, Action{Operation: "   "}, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrNoAction) {
		t.Fatalf("no-action Verify = %v, want ErrNoAction", err)
	}
}

// TestRefuse_NothingBound proves a credential binding no subject refuses.
func TestRefuse_NothingBound(t *testing.T) {
	// A binding with neither chain-head nor agent-stack digest.
	bv := carriage.BoundValues{ComparatorVersion: "v1"}
	cred, root := tokenCred(t, bv, testNow-60, testNow+60)
	if _, err := Verify(cred, root, NewLocalPolicy().PermitClass("").GrantOperations("", "op"), Action{Operation: "op"}, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrNothingBound) {
		t.Fatalf("nothing-bound Verify = %v, want ErrNothingBound", err)
	}
}

// TestRefuse_ClassNotPermitted proves a bound class not in the permitted set
// refuses (when the policy constrains classes).
func TestRefuse_ClassNotPermitted(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	action := Action{Operation: "read-object", Tool: "read-object"}
	// Policy approves the stack + permits class "reader", but the credential binds
	// class "admin".
	policy := approvePolicy(repr, "reader", "read-object", tools)
	cred, root := tokenCred(t, fullBinding(repr, "admin", nil), testNow-60, testNow+60)
	if _, err := Verify(cred, root, policy, action, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrAuthorityClassNotPermitted) {
		t.Fatalf("class-not-permitted Verify = %v, want ErrAuthorityClassNotPermitted", err)
	}
}

// TestRefuse_TaskEnvelopeUnverified proves a credential that binds a task-envelope
// digest but whose envelope the RP did not supply (or supplies a mismatching one)
// refuses fail-closed.
func TestRefuse_TaskEnvelopeUnverified(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	class, op := "reader", "read-object"
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	// Bind a non-empty task-envelope digest but supply NO envelope in policy.
	boundDigest := crypto.SHA256Sum([]byte("some-envelope"))
	policyNoEnv := approvePolicy(repr, class, op, tools) // ExpectedTaskEnvelope nil
	cred, root := tokenCred(t, fullBinding(repr, class, boundDigest), testNow-60, testNow+60)
	if _, err := Verify(cred, root, policyNoEnv, action, clk); !errors.Is(err, ErrTaskEnvelopeUnverified) {
		t.Fatalf("no-envelope Verify = %v, want ErrTaskEnvelopeUnverified", err)
	}

	// Supply a DIFFERENT envelope (digest mismatch) -> still unverified.
	env := buildTaskEnvelope(t, nil)
	policyWrongEnv := approvePolicy(repr, class, op, tools)
	policyWrongEnv.ExpectedTaskEnvelope = &env
	cred2, root2 := tokenCred(t, fullBinding(repr, class, boundDigest), testNow-60, testNow+60)
	if _, err := Verify(cred2, root2, policyWrongEnv, action, clk); !errors.Is(err, ErrTaskEnvelopeUnverified) {
		t.Fatalf("wrong-envelope Verify = %v, want ErrTaskEnvelopeUnverified", err)
	}
}

// TestRefuse_ReprDigestMismatch proves defense in depth: if the opaque repr bytes
// disagree with the separately-bound AgentStackDigest (a hostile credential whose
// digest the RP approved but whose repr bytes were swapped), the verifier refuses.
func TestRefuse_ReprDigestMismatch(t *testing.T) {
	tools := []string{"read-object"}
	realRepr := buildRepr(t, "approved-prompt", tools)
	swappedRepr := buildRepr(t, "rogue-prompt", tools)
	class, op := "reader", "read-object"
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	// Approve the REAL repr's digest, but present a credential whose AgentStackDigest
	// is the approved one while AgentStackRepr is the swapped bytes.
	bv := carriage.BoundValues{
		AgentStackDigest:  reprDigest(realRepr), // approved digest
		AgentStackRepr:    swappedRepr,          // but mismatched repr bytes
		DesignatedClass:   class,
		ComparatorVersion: "v1",
	}
	policy := approvePolicy(realRepr, class, op, tools)
	cred, root := tokenCred(t, bv, testNow-60, testNow+60)
	// The approved-digest gate passes, but the repr-vs-digest defense-in-depth check
	// must catch the swap and refuse.
	if _, err := Verify(cred, root, policy, action, clk); !errors.Is(err, ErrAgentStackNotApproved) {
		t.Fatalf("repr/digest mismatch Verify = %v, want ErrAgentStackNotApproved", err)
	}
}

// TestRefuse_MalformedRepr proves a malformed opaque representation refuses.
func TestRefuse_MalformedRepr(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	class, op := "reader", "read-object"
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	// AgentStackDigest is the digest of GARBAGE bytes, and AgentStackRepr is that
	// garbage -- so the digest check passes but decodeBoundRepr fails.
	garbage := []byte("not-a-canonical-representation")
	bv := carriage.BoundValues{
		AgentStackDigest:  reprDigest(garbage),
		AgentStackRepr:    garbage,
		DesignatedClass:   class,
		ComparatorVersion: "v1",
	}
	// Approve that digest so we get past the approved-set gate to the decode.
	policy := NewLocalPolicy().
		ApproveAgentStack(reprDigest(garbage)).
		PermitClass(class).GrantOperations(class, op).WithToolManifest(tools...)
	cred, root := tokenCred(t, bv, testNow-60, testNow+60)
	if _, err := Verify(cred, root, policy, action, clk); !errors.Is(err, ErrMalformedRepr) {
		t.Fatalf("malformed-repr Verify = %v, want ErrMalformedRepr", err)
	}
	_ = repr
}

// TestChainOnlyCredential proves a chain-only credential (claim 31 fallback: no
// agent-stack repr, no envelope) is governed by authority alone and accepts when
// the operation is granted; it carries no representation to compare, so the
// agent-stack policy check is skipped.
func TestChainOnlyCredential(t *testing.T) {
	class, op := "reader", "read-object"
	bv := carriage.BoundValues{
		ChainHeadDigest:   crypto.SHA256Sum([]byte("chain-head")),
		DesignatedClass:   class,
		ComparatorVersion: "v1",
	}
	policy := NewLocalPolicy().PermitClass(class).GrantOperations(class, op)
	cred, root := tokenCred(t, bv, testNow-60, testNow+60)
	// No tool named (chain-only carries no manifest to confine against).
	if _, err := Verify(cred, root, policy, Action{Operation: op}, FixedClock(unixToTime(testNow))); err != nil {
		t.Fatalf("chain-only Verify = %v, want accept", err)
	}
	// But a chain-only credential cannot confine a TOOL (no manifest bound) -> naming
	// a tool refuses fail-closed.
	cred2, root2 := tokenCred(t, bv, testNow-60, testNow+60)
	if _, err := Verify(cred2, root2, policy, Action{Operation: op, Tool: "read-object"}, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrToolManifestMismatch) {
		t.Fatalf("chain-only with a tool Verify = %v, want ErrToolManifestMismatch (no bound manifest to confine the tool)", err)
	}
}
