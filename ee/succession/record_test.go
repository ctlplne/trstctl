// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func sampleChain(t *testing.T) SampleChain {
	t.Helper()
	sc, err := BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://td.example", "spiffe://td.example/db", "tenant-1")
	if err != nil {
		t.Fatalf("BuildSampleChain: %v", err)
	}
	return sc
}

// TestVerifyRecord_AcceptsValid: a valid dual-attested record verifies (claim 1),
// and any single-bit tamper in any bound field or either signature is rejected.
func TestVerifyRecord_AcceptsValid(t *testing.T) {
	sc := sampleChain(t)
	rec := sc.Records[0]
	if err := VerifyRecord(rec); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	// Tamper each bound field / signature; every mutation must break verification.
	mutations := map[string]func(r *SuccessionRecord){
		"identity_id":       func(r *SuccessionRecord) { r.Fields.IdentityID += "x" },
		"tenant_id":         func(r *SuccessionRecord) { r.Fields.TenantID += "x" },
		"deployment_scope":  func(r *SuccessionRecord) { r.Fields.DeploymentScope += "x" },
		"epoch":             func(r *SuccessionRecord) { r.Fields.Epoch++ },
		"predecessor_epoch": func(r *SuccessionRecord) { r.Fields.PredecessorEpoch++ },
		"predecessor_pub":   func(r *SuccessionRecord) { r.Fields.PredecessorPub = append([]byte{0x00}, r.Fields.PredecessorPub...) },
		"successor_pub":     func(r *SuccessionRecord) { r.Fields.SuccessorPub[0] ^= 0x01 },
		"policy_ref":        func(r *SuccessionRecord) { r.Fields.PolicyRef += "x" },
		"not_before":        func(r *SuccessionRecord) { r.Fields.NotBefore++ },
		"not_after":         func(r *SuccessionRecord) { r.Fields.NotAfter++ },
		"hash_alg":          func(r *SuccessionRecord) { r.Fields.HashAlg = "SHA-512" },
		"predecessor_alg":   func(r *SuccessionRecord) { r.Fields.PredecessorAlg = crypto.ECDSAP384 },
		"successor_alg":     func(r *SuccessionRecord) { r.Fields.SuccessorAlg = crypto.RSA2048 },
		"predecessor_sig":   func(r *SuccessionRecord) { r.PredecessorAtt[0] ^= 0x01 },
		"successor_sig":     func(r *SuccessionRecord) { r.Possession.Signature[0] ^= 0x01 },
	}
	for name, mut := range mutations {
		bad := cloneRecord(rec)
		mut(&bad)
		if err := VerifyRecord(bad); err == nil {
			t.Fatalf("tamper %q was accepted", name)
		}
	}
}

// TestRecord_GenusFields: the record models the claim-25 genus — commitment
// naming stable id + both pubs/algs + epoch, a predecessor attestation, and a
// successor possession proof.
func TestRecord_GenusFields(t *testing.T) {
	rec := sampleChain(t).Records[0]
	f := rec.Fields
	if f.IdentityID == "" || f.PredecessorEpoch+1 != f.Epoch {
		t.Fatalf("genus: identity/epoch fields missing or inconsistent: %+v", f)
	}
	if f.PredecessorAlg == "" || len(f.PredecessorPub) == 0 || f.SuccessorAlg == "" || len(f.SuccessorPub) == 0 {
		t.Fatalf("genus: both pubs/algs must be present")
	}
	if len(rec.PredecessorAtt) == 0 {
		t.Fatalf("genus: predecessor attestation missing")
	}
	if rec.Possession.Kind == "" || len(rec.Possession.Signature) == 0 {
		t.Fatalf("genus: successor possession proof missing")
	}
}

// TestRecord_PossessionProofVariants: the possession proof is variant-typed and
// the record names its mechanism. The successor-signature variant verifies; the
// KEM/NIZK variants are recognized but deferred (PCAS-14).
func TestRecord_PossessionProofVariants(t *testing.T) {
	rec := sampleChain(t).Records[0]
	if rec.Possession.Kind != ProofSuccessorSignature {
		t.Fatalf("expected successor-signature variant, got %q", rec.Possession.Kind)
	}
	if err := VerifyRecord(rec); err != nil {
		t.Fatalf("successor-signature variant failed: %v", err)
	}
	for _, kind := range []PossessionProofKind{ProofDecapTranscript, ProofNIZKPoP, "bogus"} {
		bad := cloneRecord(rec)
		bad.Possession = PossessionProof{Kind: kind, Transcript: []byte{1}}
		if err := VerifyRecord(bad); err == nil {
			t.Fatalf("variant %q verified but is unsupported here", kind)
		}
	}
}

// TestRecord_NeitherAttestationAloneSuffices: a record with only the predecessor
// attestation, or only the successor possession proof, fails verification
// (claim 25 — neither limb alone establishes the succession).
func TestRecord_NeitherAttestationAloneSuffices(t *testing.T) {
	rec := sampleChain(t).Records[0]

	onlyPred := cloneRecord(rec)
	onlyPred.Possession.Signature = nil
	if err := VerifyRecord(onlyPred); err == nil {
		t.Fatal("record with only predecessor attestation verified")
	}

	onlySucc := cloneRecord(rec)
	onlySucc.PredecessorAtt = nil
	if err := VerifyRecord(onlySucc); err == nil {
		t.Fatal("record with only successor possession proof verified")
	}
}

// TestGenesis_AnchorVerifies: a chain anchored at a genesis record verifies
// end-to-end (INV-6), enforces monotonic anchoring, and rejects downgrades.
func TestGenesis_AnchorVerifies(t *testing.T) {
	sc := sampleChain(t)
	if err := VerifyGenesis(sc.TrustRootPubDER, sc.Genesis); err != nil {
		t.Fatalf("genesis attestation invalid: %v", err)
	}
	if err := VerifyChain(sc.Genesis, sc.Records, 0); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}

	// A tampered genesis public key breaks the anchor of record 0.
	badGen := sc.Genesis
	badGen.PublicKey = append([]byte{0x00}, badGen.PublicKey...)
	if err := VerifyChain(badGen, sc.Records, 0); !errors.Is(err, ErrChainAnchor) {
		t.Fatalf("tampered genesis anchor: got %v, want ErrChainAnchor", err)
	}

	// A chain head at or below last-accepted is a downgrade.
	if err := VerifyChain(sc.Genesis, sc.Records, 5); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade (head epoch <= last-accepted): got %v, want ErrDowngrade", err)
	}

	// A wrong trust-root key fails genesis attestation.
	other, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := VerifyGenesis(other.Public().DER, sc.Genesis); err == nil {
		t.Fatal("genesis verified under a wrong trust-root key")
	}
}

func cloneRecord(r SuccessionRecord) SuccessionRecord {
	out := r
	out.Fields.PredecessorPub = append([]byte(nil), r.Fields.PredecessorPub...)
	out.Fields.SuccessorPub = append([]byte(nil), r.Fields.SuccessorPub...)
	out.PredecessorAtt = append([]byte(nil), r.PredecessorAtt...)
	out.Possession.Signature = append([]byte(nil), r.Possession.Signature...)
	out.Possession.Transcript = append([]byte(nil), r.Possession.Transcript...)
	return out
}

// mintSigned builds a validly dual-signed record for the given epochs and
// predecessor linkage, so VerifyChain's structural checks can be exercised with
// records whose signatures are valid but whose epoch relationships are not.
func mintSigned(t *testing.T, be crypto.KeyGenerator, predEpoch, epoch uint64, predPub []byte, predAlg crypto.Algorithm, pred crypto.Signer) SuccessionRecord {
	t.Helper()
	succ, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	f := CommitmentFields{
		DeploymentScope: "d", IdentityID: "id", TenantID: "t",
		PredecessorEpoch: predEpoch, Epoch: epoch,
		PredecessorAlg: predAlg, PredecessorPub: predPub,
		SuccessorAlg: crypto.ECDSAP256, SuccessorPub: succ.Public().DER,
		PolicyRef: "p", HashAlg: HashAlgSHA256, NotBefore: 1000, NotAfter: 2000,
	}
	c, err := Commit(f)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	ps, err := pred.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("pred sign: %v", err)
	}
	ss, err := succ.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("succ sign: %v", err)
	}
	return SuccessionRecord{Fields: f, PredecessorAtt: ps, Possession: PossessionProof{Kind: ProofSuccessorSignature, Signature: ss}}
}

// TestVerifyChain_RejectsBadEpochs drives the structural epoch/anchor branches of
// VerifyChain with records whose dual signatures are valid but whose epoch
// relationships are inconsistent (claim 13 / INV-6 chain discipline).
func TestVerifyChain_RejectsBadEpochs(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	trustRoot, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	k0, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	genesis := GenesisRecord{DeploymentScope: "d", IdentityID: "id", TenantID: "t", Algorithm: crypto.ECDSAP256, PublicKey: k0.Public().DER, Epoch: 0}
	gd, err := GenesisDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.TrustRootAtt, err = trustRoot.Sign(gd, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatal(err)
	}

	// epoch != predecessor_epoch + 1 (0 -> 2), validly signed over its commitment.
	badIncrement := mintSigned(t, be, 0, 2, k0.Public().DER, crypto.ECDSAP256, k0)
	if err := VerifyChain(genesis, []SuccessionRecord{badIncrement}, 0); !errors.Is(err, ErrEpochNotIncrement) {
		t.Fatalf("bad increment: got %v, want ErrEpochNotIncrement", err)
	}

	// predecessor_epoch does not anchor to the genesis epoch (5 instead of 0).
	badAnchor := mintSigned(t, be, 5, 6, k0.Public().DER, crypto.ECDSAP256, k0)
	if err := VerifyChain(genesis, []SuccessionRecord{badAnchor}, 0); !errors.Is(err, ErrChainAnchor) {
		t.Fatalf("bad anchor: got %v, want ErrChainAnchor", err)
	}

	// Control: a well-formed single-record chain still verifies.
	good := mintSigned(t, be, 0, 1, k0.Public().DER, crypto.ECDSAP256, k0)
	if err := VerifyChain(genesis, []SuccessionRecord{good}, 0); err != nil {
		t.Fatalf("valid single-record chain rejected: %v", err)
	}
}
