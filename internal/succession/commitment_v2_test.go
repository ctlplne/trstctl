// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"encoding/hex"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// fixedFieldsV2 is fixedFields plus the version-2 commitment bindings.
func fixedFieldsV2() CommitmentFields {
	f := fixedFields()
	f.CommitmentVersion = 2
	f.RecordType = RecRevocation
	f.AuthzDigest = []byte{0xAA, 0xBB}
	f.AttestationEvidenceDigest = []byte{0xCC, 0xDD}
	f.AttestationType = "tpm-quote/v1"
	f.DelegationPath = "delegation:v1:abc"
	return f
}

// TestCommitmentV2_CanonicalStable freezes the v2 commitment encoding (INT-08) and
// pins that it differs from the v1 commitment of the same core fields (distinct
// domain + additional bound fields).
func TestCommitmentV2_CanonicalStable(t *testing.T) {
	const wantHex = "c13dbd5dd9393194e1c2cbe6d796bf3d36fb7b3fe8b2d7a9f9b6088008a6789b"
	c2, err := Commit(fixedFieldsV2())
	if err != nil {
		t.Fatalf("Commit v2: %v", err)
	}
	if len(c2) != 32 {
		t.Fatalf("v2 commitment length = %d, want 32", len(c2))
	}
	c1, err := Commit(fixedFields())
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) == string(c2) {
		t.Fatal("v2 commitment equals v1 for the same core fields (v2 domain/fields not bound)")
	}
	got := hex.EncodeToString(c2)
	if wantHex != "GOLDEN" && got != wantHex {
		t.Fatalf("v2 commitment golden mismatch:\n got %s\nwant %s", got, wantHex)
	}
	t.Logf("CANONICAL_COMMITMENT_V2=%s", got)
}

// TestINT08_V2CommitmentBindsRecordType proves the v2 commitment binds RecordType so
// base VerifyRecord catches a flip both ways: flipping the committed RecordType breaks
// the dual signatures, and flipping the top-level RecordType (what naive readers use)
// trips the v2 consistency check. This closes the naive-relying-party bypass.
func TestINT08_V2CommitmentBindsRecordType(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	succ, err := be.GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	fields := CommitmentFields{
		DeploymentScope: "d", IdentityID: "id", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		PolicyRef: "p", HashAlg: HashAlgSHA256, NotBefore: 1, NotAfter: 2,
		CommitmentVersion: 2, RecordType: RecRevocation,
		AuthzDigest: []byte{0x01}, AttestationEvidenceDigest: []byte{0x02}, AttestationType: "tpm",
	}
	c, err := Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := pred.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	ss, _ := succ.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	rec := SuccessionRecord{
		Fields: fields, PredecessorAtt: ps,
		Possession:  PossessionProof{Kind: ProofSuccessorSignature, Signature: ss},
		RecordType:  RecRevocation,
		AuthzDigest: []byte{0x01}, AttestationEvidenceDigest: []byte{0x02}, AttestationType: "tpm",
	}
	if err := VerifyRecord(rec); err != nil {
		t.Fatalf("valid v2 record failed to verify: %v", err)
	}

	// Flip the COMMITTED RecordType -> commitment changes -> dual signatures fail.
	bad := rec
	bad.Fields.RecordType = RecOrdinary
	if err := VerifyRecord(bad); err == nil {
		t.Fatal("flipped committed RecordType accepted (commitment binding failed)")
	}

	// Flip the TOP-LEVEL RecordType (what naive readers consume) -> consistency fails.
	bad2 := rec
	bad2.RecordType = RecOrdinary
	if err := VerifyRecord(bad2); !errors.Is(err, ErrRecordFieldMismatch) {
		t.Fatalf("flipped top-level RecordType err = %v, want ErrRecordFieldMismatch", err)
	}
}

// TestINT09_VerifyChainCatchesRevocationFlip proves the dangerous case is closed: a
// revocation tombstone (now a v2 exceptional record) cannot be hidden by flipping its
// type to ordinary, because base VerifyRecord — which VerifyChain runs per record —
// rejects the divergence. Previously only VerifyExceptional (the stricter RP path)
// caught this, so a naive relying party verifying only the chain could miss it.
func TestINT09_VerifyChainCatchesRevocationFlip(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	key, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	attest, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := BuildRevocation(key, "d", "id", "t", 0, 1, 2, attest, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fields.CommitmentVersion < 2 {
		t.Fatal("revocation record is not v2 (RecordType not committed)")
	}
	if err := VerifyRecord(rec); err != nil {
		t.Fatalf("valid revocation failed base verification: %v", err)
	}
	// Hide the revocation by flipping its type to ordinary.
	hidden := rec
	hidden.RecordType = RecOrdinary
	if err := VerifyRecord(hidden); !errors.Is(err, ErrRecordFieldMismatch) {
		t.Fatalf("hidden revocation err = %v, want ErrRecordFieldMismatch (base verification must catch it)", err)
	}
}
