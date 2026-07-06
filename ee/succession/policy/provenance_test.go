// SPDX-License-Identifier: LicenseRef-trstctl-EE

package policy_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession/policy"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	provIdentity = "spiffe://d/id"
	provTarget   = "ECDSA-P384"
)

func authority(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// buildChain signs a full finding⟵plan⟵decision provenance triple for (identity,
// target) with the given authorities.
func buildChain(t *testing.T, findingA, planA, decisionA crypto.Signer) policy.PlanChain {
	t.Helper()
	sf, err := policy.SignFinding(findingA, "find-auth", policy.Finding{
		FindingID: "f1", IdentityID: provIdentity, TenantID: "t", Algorithm: "RSA", Reason: "quantum-vulnerable", ObservedAt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := policy.SignPlan(planA, "plan-auth", policy.Plan{
		PlanID: "p1", IdentityID: provIdentity, TenantID: "t", FindingDigest: policy.FindingDigest(sf), TargetAlgorithm: provTarget, CreatedAt: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := policy.SignDecision(decisionA, "dec-auth", policy.Decision{
		DecisionID: "d1", IdentityID: provIdentity, TenantID: "t", PlanDigest: policy.PlanDigest(sp), TargetAlgorithm: provTarget, Allow: true, DecidedAt: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy.PlanChain{Finding: sf, Plan: sp, Decision: sd}
}

// TestPlanChain_DigestBindingsVerified: VerifyChain checks each authority signature
// and both digest bindings; a broken link is rejected with a specific error (claim 40).
func TestPlanChain_DigestBindingsVerified(t *testing.T) {
	a := authority(t)
	pub := a.Public().DER
	chain := buildChain(t, a, a, a)
	if err := policy.VerifyChain(chain, pub, pub, pub); err != nil {
		t.Fatalf("valid chain: %v", err)
	}

	// Broken plan→finding binding.
	badPlan := chain
	badPlan.Plan.Plan.FindingDigest = append([]byte(nil), chain.Plan.Plan.FindingDigest...)
	badPlan.Plan.Plan.FindingDigest[0] ^= 0xFF
	if err := policy.VerifyChain(badPlan, pub, pub, pub); err == nil {
		t.Fatal("tampered plan→finding digest accepted (plan sig should also break)")
	}
	// Re-sign the tampered plan so only the BINDING is wrong, not the signature.
	resignedPlan, _ := policy.SignPlan(a, "plan-auth", badPlan.Plan.Plan)
	badPlan.Plan = resignedPlan
	badPlan.Decision, _ = policy.SignDecision(a, "dec-auth", policy.Decision{
		DecisionID: "d1", IdentityID: provIdentity, TenantID: "t", PlanDigest: policy.PlanDigest(resignedPlan), TargetAlgorithm: provTarget, Allow: true, DecidedAt: 3,
	})
	if err := policy.VerifyChain(badPlan, pub, pub, pub); !errors.Is(err, policy.ErrPlanFindingBind) {
		t.Fatalf("broken plan→finding binding: got %v, want ErrPlanFindingBind", err)
	}

	// Broken decision→plan binding (re-signed decision with a wrong plan digest).
	badDec := chain
	wrongDigest := append([]byte(nil), chain.Decision.Decision.PlanDigest...)
	wrongDigest[0] ^= 0xFF
	d := chain.Decision.Decision
	d.PlanDigest = wrongDigest
	badDec.Decision, _ = policy.SignDecision(a, "dec-auth", d)
	if err := policy.VerifyChain(badDec, pub, pub, pub); !errors.Is(err, policy.ErrDecisionPlanBind) {
		t.Fatalf("broken decision→plan binding: got %v, want ErrDecisionPlanBind", err)
	}

	// Wrong authority for the decision.
	other := authority(t)
	if err := policy.VerifyChain(chain, pub, pub, other.Public().DER); !errors.Is(err, policy.ErrDecisionSig) {
		t.Fatalf("wrong decision authority: got %v, want ErrDecisionSig", err)
	}
}

// TestPolicyRef_IsDigestOfRecordedDecision: policy_ref equals the digest of the
// recorded decision; a mismatch is refused by the in-signer verifier (claim 24).
func TestPolicyRef_IsDigestOfRecordedDecision(t *testing.T) {
	a := authority(t)
	pub := a.Public().DER
	chain := buildChain(t, a, a, a)

	if policy.PolicyRef(chain) != "sha256:"+hexOf(policy.DecisionDigest(chain.Decision)) {
		t.Fatal("PolicyRef is not the hex digest of the recorded decision")
	}

	encoded, _ := policy.EncodeChain(chain)
	v := policy.ProvenanceVerifier{FindingAuthorityDER: pub, PlanAuthorityDER: pub, DecisionAuthorityDER: pub}

	// Correct policy_ref → accepted.
	if err := v.Verify(signing.MintRequest{IdentityID: provIdentity, TargetAlgorithm: crypto.Algorithm(provTarget), PolicyRef: policy.PolicyRef(chain), PolicyDecision: encoded}); err != nil {
		t.Fatalf("correct policy_ref: %v", err)
	}
	// Mismatched policy_ref → refused.
	if err := v.Verify(signing.MintRequest{IdentityID: provIdentity, TargetAlgorithm: crypto.Algorithm(provTarget), PolicyRef: "sha256:deadbeef", PolicyDecision: encoded}); !errors.Is(err, policy.ErrPolicyRefMismatch) {
		t.Fatalf("mismatched policy_ref: got %v, want ErrPolicyRefMismatch", err)
	}
}

// TestPolicy_DecisionRecorded: minting with a decision that was never recorded fails
// where recording is configured; the recorded decision is queryable (claim 24).
func TestPolicy_DecisionRecorded(t *testing.T) {
	a := authority(t)
	pub := a.Public().DER
	chain := buildChain(t, a, a, a)
	encoded, _ := policy.EncodeChain(chain)
	ledger := policy.NewMemDecisionLedger()
	v := policy.ProvenanceVerifier{FindingAuthorityDER: pub, PlanAuthorityDER: pub, DecisionAuthorityDER: pub, Recorded: ledger}
	req := signing.MintRequest{IdentityID: provIdentity, TargetAlgorithm: crypto.Algorithm(provTarget), PolicyRef: policy.PolicyRef(chain), PolicyDecision: encoded}

	// Not recorded → refused.
	if err := v.Verify(req); !errors.Is(err, policy.ErrDecisionNotRecorded) {
		t.Fatalf("unrecorded decision: got %v, want ErrDecisionNotRecorded", err)
	}
	// Record, then it verifies and is queryable.
	if err := ledger.Record(chain.Decision); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(req); err != nil {
		t.Fatalf("recorded decision: %v", err)
	}
	if _, ok := ledger.Get(policy.DecisionDigest(chain.Decision)); !ok {
		t.Fatal("recorded decision is not queryable from the ledger")
	}
}

// TestPlanChain_DecisionTraceableToFinding: from a published record's policy_ref an
// auditor walks policy_ref → decision → plan → finding (claim 40).
func TestPlanChain_DecisionTraceableToFinding(t *testing.T) {
	a := authority(t)
	pub := a.Public().DER
	chain := buildChain(t, a, a, a)
	publishedPolicyRef := policy.PolicyRef(chain) // as bound in the succession commitment

	finding, err := policy.TraceToFinding(publishedPolicyRef, chain, pub, pub, pub)
	if err != nil {
		t.Fatalf("trace to finding: %v", err)
	}
	if finding.FindingID != "f1" || finding.IdentityID != provIdentity {
		t.Fatalf("traced finding wrong: %+v", finding)
	}
	// A policy_ref that does not match the presented chain cannot be traced.
	if _, err := policy.TraceToFinding("sha256:deadbeef", chain, pub, pub, pub); !errors.Is(err, policy.ErrPolicyRefMismatch) {
		t.Fatalf("mismatched policy_ref trace: got %v, want ErrPolicyRefMismatch", err)
	}
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
