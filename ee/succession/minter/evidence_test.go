// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter_test

import (
	"bytes"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
)

const attestSignerID = "signer-1"

func attestKey(t *testing.T) (crypto.Signer, map[string][]byte) {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s, map[string][]byte{attestSignerID: s.Public().DER}
}

// TestRecord_CarriesSignerAttestation: every minted record (ordinary and break-glass)
// carries a signer-attestation countersignature that verifies and names the signer;
// a stripped attestation fails AttestedVerify (PCAS-claim-28 / INV-13).
func TestRecord_CarriesSignerAttestation(t *testing.T) {
	attest, roster := attestKey(t)

	// Ordinary mint.
	m, _, _ := setup(t, minter.WithAttestation(attest, attestSignerID))
	res, err := m.MintSuccessor(ctx, baseReq())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := succession.AttestedVerify(rec, roster)
	if err != nil || signer != attestSignerID {
		t.Fatalf("ordinary record attestation: signer=%q err=%v", signer, err)
	}
	// A stripped countersignature is rejected — no unattested record is accepted (AC5).
	stripped := rec
	stripped.SignerAttestation = nil
	if _, err := succession.AttestedVerify(stripped, roster); !errors.Is(err, succession.ErrSignerAttestation) {
		t.Fatalf("stripped attestation: got %v, want ErrSignerAttestation", err)
	}

	// Break-glass mint (a strength downgrade with a valid token) is attested too.
	be := crypto.NewSoftwareBackend()
	authority, _ := be.GenerateKey(crypto.ECDSAP256)
	bg := minter.NewSignedBreakGlassAuthorizer(authority.Public().DER)
	mbg, err := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(),
		minter.WithStrengthOrdering(bg), minter.WithAttestation(attest, attestSignerID))
	if err != nil {
		t.Fatal(err)
	}
	req := downgradeReq()
	req.BreakGlass = breakGlassToken(t, authority, req, "bg-1")
	bgRes, err := mbg.MintSuccessor(ctx, req)
	if err != nil {
		t.Fatalf("break-glass mint: %v", err)
	}
	bgRec, _ := minter.DecodeRecord(bgRes.EncodedRecord)
	if s, err := succession.VerifyAttestation(roster, bgRec); err != nil || s != attestSignerID {
		t.Fatalf("break-glass record not attested: signer=%q err=%v", s, err)
	}
}

// TestRecord_CarriesAuthzDigest / TestAuthzDigest_VerifiableFromRecord: a minted
// record binds a digest of the dual-control authorization artifact, and a third party
// recomputes it from the published artifact (PCAS-claim-42).
func TestRecord_CarriesAuthzDigest(t *testing.T) {
	attest, _ := attestKey(t)
	be := crypto.NewSoftwareBackend()
	authority, _ := be.GenerateKey(crypto.ECDSAP256)
	m, _, _ := setupWith(t, be,
		minter.WithDualControl(minter.NewSignedTokenAuthorizer(authority.Public().DER)),
		minter.WithAttestation(attest, attestSignerID))

	req := baseReq()
	req.Authorization = mintToken(t, authority, req, minter.RequestParamsDigest(req), "n1")
	res, err := m.MintSuccessor(ctx, req)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rec, _ := minter.DecodeRecord(res.EncodedRecord)

	if !bytes.Equal(rec.AuthzDigest, succession.AuthzDigest(req.Authorization)) {
		t.Fatal("record authz_digest does not match the authorization artifact")
	}
	// Third-party verification from the published artifact.
	if err := succession.VerifyAuthzDigest(rec, req.Authorization); err != nil {
		t.Fatalf("authz_digest verify: %v", err)
	}
	// A different artifact does not match.
	if succession.VerifyAuthzDigest(rec, append(append([]byte(nil), req.Authorization...), 0x00)) == nil {
		t.Fatal("authz_digest verified against a tampered authorization artifact")
	}
}

// TestRefusal_SignedArtifact: each refusal class (epoch, strength, policy,
// dual-control) yields a signed refusal artifact naming the request + violated
// constraint (PCAS-claim-41).
func TestRefusal_SignedArtifact(t *testing.T) {
	attest, _ := attestKey(t)
	attestPub := attest.Public().DER

	assertRefusal := func(t *testing.T, err error, wantConstraint string) {
		t.Helper()
		var refErr *minter.RefusalError
		if !errors.As(err, &refErr) {
			t.Fatalf("refusal did not carry a signed artifact: %v", err)
		}
		if e := succession.VerifyRefusal(attestPub, refErr.Artifact); e != nil {
			t.Fatalf("refusal artifact does not verify: %v", e)
		}
		if refErr.Artifact.Constraint != wantConstraint {
			t.Fatalf("refusal constraint = %q, want %q", refErr.Artifact.Constraint, wantConstraint)
		}
		if len(refErr.Artifact.RequestDigest) == 0 || refErr.Artifact.SignerID != attestSignerID {
			t.Fatalf("refusal artifact missing request digest / signer id: %+v", refErr.Artifact)
		}
	}

	// Epoch.
	me, _, _ := setup(t, minter.WithAttestation(attest, attestSignerID))
	if _, err := me.MintSuccessor(ctx, baseReq()); err != nil {
		t.Fatal(err)
	}
	_, err := me.MintSuccessor(ctx, baseReq()) // stale epoch
	if !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("epoch: want ErrEpochNotCurrent, got %v", err)
	}
	assertRefusal(t, err, succession.RefusalEpoch)

	// Policy (missing decision).
	be := crypto.NewSoftwareBackend()
	authority, _ := be.GenerateKey(crypto.ECDSAP256)
	mp, _, _ := setupWith(t, be, minter.WithPolicy(minter.SignedPolicyAuthorizer{AuthorityPubDER: authority.Public().DER}), minter.WithAttestation(attest, attestSignerID))
	_, err = mp.MintSuccessor(ctx, baseReq())
	assertRefusal(t, err, succession.RefusalPolicy)

	// Dual-control (missing token).
	ma, _, _ := setupWith(t, be, minter.WithDualControl(minter.NewSignedTokenAuthorizer(authority.Public().DER)), minter.WithAttestation(attest, attestSignerID))
	_, err = ma.MintSuccessor(ctx, baseReq())
	assertRefusal(t, err, succession.RefusalDualControl)

	// Strength downgrade (no break-glass).
	ms, err := minter.New(pqPred(t, be, "ML-DSA-65"), be, newMemFloor(), minter.WithStrengthOrdering(nil), minter.WithAttestation(attest, attestSignerID))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ms.MintSuccessor(ctx, downgradeReq())
	assertRefusal(t, err, succession.RefusalStrength)
}
