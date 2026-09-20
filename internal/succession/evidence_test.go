// SPDX-License-Identifier: BUSL-1.1

package succession_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
)

func evSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func evFields() succession.CommitmentFields {
	return succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: []byte{0x01},
		SuccessorAlg: crypto.ECDSAP256, SuccessorPub: []byte{0x02},
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
}

// TestAttestation_BindsAnyRecord: the attestation primitive (used by KEM, recovery,
// and the minter) names the signer, binds the authz_digest, and rejects a tampered
// or unattested record (PCAS-claim-28 / PCAS-claim-42 / INV-13).
func TestAttestation_BindsAnyRecord(t *testing.T) {
	attest := evSigner(t)
	roster := map[string][]byte{"signer-x": attest.Public().DER}

	rec := succession.SuccessionRecord{Fields: evFields(), AuthzDigest: succession.AuthzDigest([]byte("authz"))}
	att, err := succession.Attest(attest, "signer-x", rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.SignerAttestation = att

	if id, err := succession.VerifyAttestation(roster, rec); err != nil || id != "signer-x" {
		t.Fatalf("verify attestation: id=%q err=%v", id, err)
	}
	if id, err := succession.MintingSignerID(rec); err != nil || id != "signer-x" {
		t.Fatalf("minting signer id: %q err=%v", id, err)
	}
	// The attestation binds authz_digest: changing it breaks the attestation.
	tampered := rec
	tampered.AuthzDigest = succession.AuthzDigest([]byte("other"))
	if _, err := succession.VerifyAttestation(roster, tampered); err == nil {
		t.Fatal("attestation is not bound to authz_digest")
	}
	// An unknown / unrostered signer fails.
	if _, err := succession.VerifyAttestation(map[string][]byte{}, rec); !errors.Is(err, succession.ErrSignerAttestation) {
		t.Fatalf("unknown signer: got %v, want ErrSignerAttestation", err)
	}
}

// TestRefusal_RecordedAsAuditEvent: a signed refusal artifact round-trips as an AN-2
// ledger event and remains verifiable; tampering the recorded constraint breaks it
// (PCAS-claim-41).
func TestRefusal_RecordedAsAuditEvent(t *testing.T) {
	attest := evSigner(t)
	art, err := succession.SignRefusal(attest, succession.RefusalArtifact{
		SignerID: "signer-x", IdentityID: "spiffe://d/id", TenantID: "t",
		RequestDigest: []byte{1, 2, 3}, Constraint: succession.RefusalTenant, IssuedAt: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyRefusal(attest.Public().DER, art); err != nil {
		t.Fatalf("refusal verify: %v", err)
	}

	ev, err := succession.Encode(succession.RefusalV1{
		IdentityID: art.IdentityID, TenantID: art.TenantID, SignerID: art.SignerID,
		Constraint: art.Constraint, RequestDigest: art.RequestDigest, IssuedAt: art.IssuedAt, Signature: art.Signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != succession.TypeRefusal {
		t.Fatalf("event type = %q, want %q", ev.Type, succession.TypeRefusal)
	}
	p, err := succession.Decode(ev)
	if err != nil {
		t.Fatal(err)
	}
	rv, ok := p.(succession.RefusalV1)
	if !ok || rv.Constraint != succession.RefusalTenant || rv.SignerID != "signer-x" {
		t.Fatalf("decoded refusal event wrong: %+v", p)
	}
	// The artifact reconstructed from the recorded event still verifies.
	reArt := succession.RefusalArtifact{
		SignerID: rv.SignerID, IdentityID: rv.IdentityID, TenantID: rv.TenantID,
		RequestDigest: rv.RequestDigest, Constraint: rv.Constraint, IssuedAt: rv.IssuedAt, Signature: rv.Signature,
	}
	if err := succession.VerifyRefusal(attest.Public().DER, reArt); err != nil {
		t.Fatalf("refusal artifact from event does not verify: %v", err)
	}
	bad := reArt
	bad.Constraint = succession.RefusalEpoch
	if succession.VerifyRefusal(attest.Public().DER, bad) == nil {
		t.Fatal("a tampered refusal constraint verified")
	}
}
