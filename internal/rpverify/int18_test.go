// SPDX-License-Identifier: BUSL-1.1

package rpverify_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rpverify"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/translog"
)

// TestINT18_ExceptionalInclusionUsesRealVerifier proves the relying party's
// exceptional-record inclusion check is the REAL RFC-6962 Merkle verifier against a
// signed transparency-log head — not an injectable closure. A revocation record is
// appended to a real signed log, a self-contained proof is produced, and the RP
// accepts it under the log's key; every forgery (wrong log key, tampered head, a
// proof for a different record, an unsigned/absent key) is rejected.
func TestINT18_ExceptionalInclusionUsesRealVerifier(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	cur, _ := be.GenerateKey(crypto.ECDSAP256)
	attest, _ := be.GenerateKey(crypto.ECDSAP256)
	logKey, _ := be.GenerateKey(crypto.ECDSAP256)
	roster := map[string][]byte{"signer-1": attest.Public().DER}

	// A real revocation (exceptional) record.
	rec, err := succession.BuildRevocation(cur, "spiffe://d", "spiffe://d/id", "t", 0, 1, 1000, attest, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := succession.Commit(rec.Fields)
	if err != nil {
		t.Fatal(err)
	}

	// Append it to a REAL signed log and attach a real, self-contained proof.
	l := translog.New(logKey)
	_, _, _ = l.Append([]byte("prior-entry"))
	idx, _, err := l.Append(leaf)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := l.Prove(idx)
	if err != nil {
		t.Fatal(err)
	}
	rec.InclusionProof = translog.EncodeProof(proof)

	// Accept under the correct log key.
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: roster, STHVerifyKeyDER: logKey.Public().DER}); err != nil {
		t.Fatalf("real inclusion proof rejected: %v", err)
	}

	// Wrong log key -> STH signature fails (rejected). A verifier cannot be fooled by a
	// head signed by an untrusted key.
	other, _ := be.GenerateKey(crypto.ECDSAP256)
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: roster, STHVerifyKeyDER: other.Public().DER}); err == nil {
		t.Fatal("wrong log key accepted; STH signature not checked")
	}

	// No trusted log key -> fails closed. This is the crux of INT-18: there is no
	// injected closure that can satisfy "mandatory inclusion" without a real proof.
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: roster}); err == nil {
		t.Fatal("missing log key accepted; inclusion did not fail closed")
	}

	// A valid proof for a DIFFERENT record does not transfer: the RP recomputes the
	// leaf from THIS record's commitment, so a swapped proof is not included.
	other2, _ := be.GenerateKey(crypto.ECDSAP256)
	rec2, _ := succession.BuildRevocation(other2, "spiffe://d", "spiffe://d/id2", "t", 0, 1, 1000, attest, "signer-1")
	leaf2, _ := succession.Commit(rec2.Fields)
	l2 := translog.New(logKey)
	i2, _, _ := l2.Append(leaf2)
	p2, _ := l2.Prove(i2)
	rec.InclusionProof = translog.EncodeProof(p2) // proof for rec2's leaf, attached to rec
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: roster, STHVerifyKeyDER: logKey.Public().DER}); !errors.Is(err, translog.ErrProofInclusion) {
		t.Fatalf("swapped proof: got %v, want ErrProofInclusion", err)
	}
}
