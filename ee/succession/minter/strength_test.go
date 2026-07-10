// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter_test

import (
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// classSigner reports a chosen algorithm identifier (its strength class) while
// signing with a real classical key, so strength-ordering logic can be exercised
// without post-quantum key backends.
type classSigner struct {
	inner crypto.Signer
	alg   crypto.Algorithm
}

func (c classSigner) Public() crypto.PublicKey {
	return crypto.PublicKey{Algorithm: c.alg, DER: c.inner.Public().DER}
}
func (c classSigner) Algorithm() crypto.Algorithm { return c.alg }
func (c classSigner) Sign(m []byte, o crypto.SignOptions) ([]byte, error) {
	return c.inner.Sign(m, o)
}

func pqPred(t *testing.T, be crypto.KeyGenerator, alg crypto.Algorithm) mapResolver {
	t.Helper()
	inner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return mapResolver{"pred": classSigner{inner: inner, alg: alg}}
}

// downgradeReq: a classical target from a (PQ/hybrid) predecessor => a downgrade.
func downgradeReq() signing.MintRequest {
	return signing.MintRequest{
		IdentityID: "spiffe://d/db", TenantID: "t1", DeploymentScope: "spiffe://d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "p", NotBefore: 1, NotAfter: 1000,
	}
}

func breakGlassToken(t *testing.T, authority crypto.Signer, req signing.MintRequest, nonce string) []byte {
	t.Helper()
	payload, err := json.Marshal(minter.BreakGlassToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID, DeploymentScope: req.DeploymentScope,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch, TargetAlgorithm: req.TargetAlgorithm, Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := minter.SignEnvelope(authority, payload)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestMint_RefusesStrengthDowngrade: PQ->classical and hybrid->classical are
// refused without break-glass (claim 17 / INV-8).
func TestMint_RefusesStrengthDowngrade(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	for _, predAlg := range []crypto.Algorithm{"ML-DSA-65", "Hybrid-Ed25519-Dilithium3"} {
		m, err := minter.New(pqPred(t, be, predAlg), be, newMemFloor(), minter.WithStrengthOrdering(nil))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.MintSuccessor(ctx, downgradeReq()); !errors.Is(err, minter.ErrStrengthDowngrade) {
			t.Fatalf("predecessor %s: got %v, want ErrStrengthDowngrade", predAlg, err)
		}
	}
	// A same-class succession is unaffected even with strength ordering on
	// (regression on PCAS-05): classical -> classical is not a downgrade.
	same, err := minter.New(pqPred(t, be, crypto.ECDSAP256), be, newMemFloor(), minter.WithStrengthOrdering(nil))
	if err != nil {
		t.Fatal(err)
	}
	req := downgradeReq()
	req.TargetAlgorithm = crypto.ECDSAP384
	if _, err := same.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("same-class succession refused: %v", err)
	}
}

// TestMint_BreakGlassOverride_MofN: with a valid break-glass token the downgrade
// mints and the record carries the break-glass marker (claim 17).
func TestMint_BreakGlassOverride_MofN(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	bg := minter.NewSignedBreakGlassAuthorizer(authority.Public().DER)
	m, err := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(), minter.WithStrengthOrdering(bg))
	if err != nil {
		t.Fatal(err)
	}
	req := downgradeReq()
	req.BreakGlass = breakGlassToken(t, authority, req, "bg-1")
	res, err := m.MintSuccessor(ctx, req)
	if err != nil {
		t.Fatalf("break-glass mint refused: %v", err)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.BreakGlassAuth) == 0 {
		t.Fatal("minted break-glass record is missing the break-glass marker")
	}
}

// TestBreakGlass_TokenBoundSingleUse: a replayed token, or one bound to a
// different target algorithm, is refused (claim 17 / INV-8).
func TestBreakGlass_TokenBoundSingleUse(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	bg := minter.NewSignedBreakGlassAuthorizer(authority.Public().DER)

	// Single-use: a nonce spent on one minter is refused on another sharing the
	// authorizer.
	m1, _ := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(), minter.WithStrengthOrdering(bg))
	req := downgradeReq()
	req.BreakGlass = breakGlassToken(t, authority, req, "same-nonce")
	if _, err := m1.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("first break-glass mint: %v", err)
	}
	m2, _ := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(), minter.WithStrengthOrdering(bg))
	req2 := downgradeReq()
	req2.BreakGlass = breakGlassToken(t, authority, req2, "same-nonce")
	if _, err := m2.MintSuccessor(ctx, req2); !errors.Is(err, minter.ErrStrengthDowngrade) {
		t.Fatalf("replayed break-glass nonce: got %v, want ErrStrengthDowngrade", err)
	}

	// Rebound: a token bound to a different target algorithm is refused.
	m3, _ := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(), minter.WithStrengthOrdering(bg))
	req3 := downgradeReq()
	wrong := req3
	wrong.TargetAlgorithm = crypto.RSA2048
	req3.BreakGlass = breakGlassToken(t, authority, wrong, "n2")
	if _, err := m3.MintSuccessor(ctx, req3); !errors.Is(err, minter.ErrStrengthDowngrade) {
		t.Fatalf("rebound break-glass token: got %v, want ErrStrengthDowngrade", err)
	}

	// Cross-deployment: a token bound to a DIFFERENT deployment scope cannot authorize
	// this deployment's downgrade (security review MEDIUM: DeploymentScope is bound).
	m4, _ := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(), minter.WithStrengthOrdering(bg))
	req4 := downgradeReq()
	foreign := req4
	foreign.DeploymentScope = "spiffe://other-deployment"
	req4.BreakGlass = breakGlassToken(t, authority, foreign, "n3")
	if _, err := m4.MintSuccessor(ctx, req4); !errors.Is(err, minter.ErrStrengthDowngrade) {
		t.Fatalf("cross-deployment break-glass token: got %v, want ErrStrengthDowngrade", err)
	}
}
