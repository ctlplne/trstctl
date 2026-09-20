// SPDX-License-Identifier: BUSL-1.1

package minter_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession/minter"
	"trstctl.com/trstctl/internal/succession/policy"
)

// countingKeygen counts successor-key generations so a test can prove provenance is
// verified BEFORE keygen (a refused mint generates no key).
type countingKeygen struct {
	inner crypto.KeyGenerator
	n     int
}

func (c *countingKeygen) GenerateKey(a crypto.Algorithm) (crypto.Signer, error) {
	c.n++
	return c.inner.GenerateKey(a)
}

func provChain(t *testing.T, a crypto.Signer, identity, target string) policy.PlanChain {
	t.Helper()
	sf, _ := policy.SignFinding(a, "fa", policy.Finding{FindingID: "f", IdentityID: identity, TenantID: "t1", Algorithm: "RSA", Reason: "weak", ObservedAt: 1})
	sp, _ := policy.SignPlan(a, "pa", policy.Plan{PlanID: "p", IdentityID: identity, TenantID: "t1", FindingDigest: policy.FindingDigest(sf), TargetAlgorithm: target, CreatedAt: 2})
	sd, _ := policy.SignDecision(a, "da", policy.Decision{DecisionID: "d", IdentityID: identity, TenantID: "t1", PlanDigest: policy.PlanDigest(sp), TargetAlgorithm: target, Allow: true, DecidedAt: 3})
	return policy.PlanChain{Finding: sf, Plan: sp, Decision: sd}
}

// TestPlanChain_VerifiedBeforeKeygen: the minter verifies the provenance chain before
// successor keygen — a valid chain mints (keygen once) and binds policy_ref in the
// commitment; a broken chain refuses before any key is generated (PCAS-claims-24, 40).
func TestPlanChain_VerifiedBeforeKeygen(t *testing.T) {
	a, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pub := a.Public().DER
	const identity, target = "spiffe://td.example/db", "ECDSA-P384"
	chain := provChain(t, a, identity, target)
	encoded, _ := policy.EncodeChain(chain)
	pv := policy.ProvenanceVerifier{FindingAuthorityDER: pub, PlanAuthorityDER: pub, DecisionAuthorityDER: pub}

	mk := func() (*minter.Minter, *countingKeygen) {
		ck := &countingKeygen{inner: crypto.NewSoftwareBackend()}
		pred, _ := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
		m, err := minter.New(mapResolver{"pred": pred}, ck, newMemFloor(), minter.WithPlanProvenance(pv))
		if err != nil {
			t.Fatal(err)
		}
		return m, ck
	}

	// Valid chain + matching policy_ref → mints, and the record binds policy_ref.
	m, ck := mk()
	req := baseReq()
	req.PolicyDecision = encoded
	req.PolicyRef = policy.PolicyRef(chain)
	res, err := m.MintSuccessor(ctx, req)
	if err != nil {
		t.Fatalf("valid provenance mint: %v", err)
	}
	if ck.n != 1 {
		t.Fatalf("keygen called %d times, want 1", ck.n)
	}
	rec, _ := minter.DecodeRecord(res.EncodedRecord)
	if rec.Fields.PolicyRef != policy.PolicyRef(chain) {
		t.Fatal("minted commitment does not bind the provenance policy_ref")
	}

	// Broken decision→plan binding → refused before keygen.
	m2, ck2 := mk()
	bad := chain
	d := bad.Decision.Decision
	d.PlanDigest = append([]byte(nil), d.PlanDigest...)
	d.PlanDigest[0] ^= 0xFF
	bad.Decision, _ = policy.SignDecision(a, "da", d)
	badEncoded, _ := policy.EncodeChain(bad)
	req2 := baseReq()
	req2.PolicyDecision = badEncoded
	req2.PolicyRef = policy.PolicyRef(bad) // matches the broken chain, so the binding is what fails
	if _, err := m2.MintSuccessor(ctx, req2); err == nil {
		t.Fatal("mint with a broken provenance chain succeeded")
	}
	if ck2.n != 0 {
		t.Fatalf("keygen called %d times on a refused mint, want 0 (provenance is before keygen)", ck2.n)
	}
}
