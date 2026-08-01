// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestINT06_DurableDualControlSingleUseSurvivesRestart proves single-use survives a
// signer restart (PCAS-claim-5): a durable dual-control authorizer consumes a token; a
// FRESH authorizer over the same custody dir refuses the replay. With the in-memory
// store the fresh authorizer would accept it — a single-use bypass.
func TestINT06_DurableDualControlSingleUseSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pub := authority.Public().DER

	req := signing.MintRequest{
		IdentityID: "spiffe://d/int06", TenantID: "t", DeploymentScope: "d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "p",
	}
	pd := minter.RequestParamsDigest(req)
	payload, _ := json.Marshal(minter.AuthorizationToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch, TargetAlgorithm: req.TargetAlgorithm,
		ParamsDigest: pd, Nonce: "nonce-1",
	})
	token, err := minter.SignEnvelope(authority, payload)
	if err != nil {
		t.Fatal(err)
	}

	a1, err := minter.NewDurableSignedTokenAuthorizer(pub, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a1.VerifyAndConsume(token, req, pd); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}

	// "Restart": a fresh authorizer over the SAME custody dir loads the consumed nonce
	// and refuses the replay.
	a2, err := minter.NewDurableSignedTokenAuthorizer(pub, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.VerifyAndConsume(token, req, pd); err == nil {
		t.Fatal("post-restart token replay accepted; single-use did not survive restart")
	}
}

// TestDurableSpentStore_ReloadsConsumedNonces: consumed nonces reload across a fresh
// store on the same dir.
func TestDurableSpentStore_ReloadsConsumedNonces(t *testing.T) {
	dir := t.TempDir()
	s1, err := minter.NewDurableSpentStore(dir, "spent")
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := s1.Consume("n1"); used {
		t.Fatal("n1 unexpectedly already spent")
	}
	s2, err := minter.NewDurableSpentStore(dir, "spent")
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := s2.Consume("n1"); !used {
		t.Fatal("n1 not seen as spent after reload (durability failed)")
	}
	if used, _ := s2.Consume("n2"); used {
		t.Fatal("n2 unexpectedly already spent")
	}
}
