// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/kem"
	"trstctl.com/trstctl/ee/succession/retirement"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
	"trstctl.com/trstctl/internal/events"
)

const kemAlg = "ML-KEM-768"

func ecdsa(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func genKEM(t *testing.T) *eepqc.KEMPrivateKey {
	t.Helper()
	k, err := eepqc.GenerateKEMKey(kemAlg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, s crypto.Signer, msg []byte) []byte {
	t.Helper()
	sig, err := s.Sign(msg, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func baseFields(pred crypto.Signer, succAlg crypto.Algorithm, succPub []byte) succession.CommitmentFields {
	return succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succAlg, SuccessorPub: succPub,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
}

// TestKEMPossessionProof_Decapsulation: a valid decap transcript verifies (Variant A);
// a tampered transcript or a wrong-key decapsulation is rejected (PCAS-claim-15).
func TestKEMPossessionProof_Decapsulation(t *testing.T) {
	pred := ecdsa(t)
	succKem := genKEM(t)
	fields := baseFields(pred, crypto.Algorithm(kemAlg), succKem.Public().DER)
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	predAtt := sign(t, pred, commitment)

	ct, ss, err := kem.EncapsulateChallenge(kemAlg, succKem.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := kem.Respond(succKem, ct, commitment)
	if err != nil {
		t.Fatal(err)
	}
	rec := kem.BuildInteractiveRecord(fields, predAtt, tr)
	if err := kem.VerifyInteractiveRecord(rec, ss); err != nil {
		t.Fatalf("valid decap transcript: %v", err)
	}

	// Tampered response.
	badTr := tr
	badTr.Response = append([]byte(nil), tr.Response...)
	badTr.Response[0] ^= 0xFF
	if err := kem.VerifyInteractiveRecord(kem.BuildInteractiveRecord(fields, predAtt, badTr), ss); !errors.Is(err, kem.ErrDecapProof) {
		t.Fatalf("tampered transcript: got %v, want ErrDecapProof", err)
	}

	// Wrong-key decapsulation: a different KEM key decapsulating the same ciphertext
	// yields a different shared secret, so the response cannot match.
	wrongTr, err := kem.Respond(genKEM(t), ct, commitment)
	if err != nil {
		t.Fatal(err)
	}
	if err := kem.VerifyInteractiveRecord(kem.BuildInteractiveRecord(fields, predAtt, wrongTr), ss); !errors.Is(err, kem.ErrDecapProof) {
		t.Fatalf("wrong-key decap: got %v, want ErrDecapProof", err)
	}
}

// TestKEMSuccession_PairedSigningKeyVariant: the paired epoch-bound signing key is
// named in the commitment and its binding names the KEM public key; the record
// verifies offline for an arbitrary third party (Variant B, PCAS-claim-15).
func TestKEMSuccession_PairedSigningKeyVariant(t *testing.T) {
	pred := ecdsa(t)
	paired := ecdsa(t) // epoch-bound signing key paired with the KEM identity
	succKem := genKEM(t)
	fields := baseFields(pred, paired.Algorithm(), paired.Public().DER)
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := kem.SignKEMBinding(paired, commitment, kemAlg, succKem.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	rec := kem.PairedRecord{
		Base: succession.SuccessionRecord{
			Fields: fields, PredecessorAtt: sign(t, pred, commitment),
			Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: sign(t, paired, commitment)},
		},
		KEMAlg: kemAlg, KEMPub: succKem.Public().DER, Binding: binding,
	}
	// Publicly verifiable: no challenger secret required.
	if err := kem.VerifyPaired(rec); err != nil {
		t.Fatalf("Variant B verify: %v", err)
	}
	if !kem.PubliclyVerifiable(rec.Base.Possession.Kind) || kem.RequirePublicVerifiability(rec.Base.Possession.Kind) != nil {
		t.Fatal("Variant B must be publicly verifiable")
	}
	// Tampering the named KEM public key breaks the binding.
	bad := rec
	bad.KEMPub = append([]byte(nil), rec.KEMPub...)
	bad.KEMPub[0] ^= 0xFF
	if err := kem.VerifyPaired(bad); !errors.Is(err, kem.ErrBinding) {
		t.Fatalf("tampered KEM pub: got %v, want ErrBinding", err)
	}
}

// TestKEMSuccession_RecordNamesProofMechanism: a record must name exactly one
// mechanism and carry exactly that limb; naming one but carrying the other is
// rejected, and the interactive mechanism is flagged non-publicly-verifiable (PCAS-claim-15).
func TestKEMSuccession_RecordNamesProofMechanism(t *testing.T) {
	cases := []succession.PossessionProof{
		{Kind: succession.ProofSuccessorSignature, Signature: []byte{1}, Transcript: []byte{2}}, // sig names, carries transcript too
		{Kind: succession.ProofSuccessorSignature},                                              // sig names, carries nothing
		{Kind: succession.ProofDecapTranscript, Transcript: []byte{1}, Signature: []byte{2}},    // decap names, carries a signature
		{Kind: succession.ProofDecapTranscript},                                                 // decap names, carries nothing
		{Kind: succession.PossessionProofKind("mystery")},                                       // unknown
	}
	for i, p := range cases {
		if err := kem.VerifyNamesMechanism(p); !errors.Is(err, kem.ErrMechanismMismatch) {
			t.Fatalf("case %d: got %v, want ErrMechanismMismatch", i, err)
		}
	}
	// Correctly-named records pass.
	if err := kem.VerifyNamesMechanism(succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := kem.VerifyNamesMechanism(succession.PossessionProof{Kind: succession.ProofDecapTranscript, Transcript: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	// The interactive mechanism must be flagged where public verifiability is required.
	if err := kem.RequirePublicVerifiability(succession.ProofDecapTranscript); !errors.Is(err, kem.ErrNotPubliclyVerif) {
		t.Fatalf("decap transcript must be flagged non-public: %v", err)
	}
}

// --- predecessor-KEM (PCAS-claim-30) --------------------------------------------

func predKEMSetup(t *testing.T) (kem.PredecessorKEMRecord, succession.CommitmentFields, []byte, []byte) {
	t.Helper()
	predKem, succKem := genKEM(t), genKEM(t)
	fields := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: crypto.Algorithm(kemAlg), PredecessorPub: predKem.Public().DER,
		SuccessorAlg: crypto.Algorithm(kemAlg), SuccessorPub: succKem.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	predCt, predSS, err := kem.EncapsulateChallenge(kemAlg, predKem.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	predTr, err := kem.Respond(predKem, predCt, commitment)
	if err != nil {
		t.Fatal(err)
	}
	succCt, succSS, err := kem.EncapsulateChallenge(kemAlg, succKem.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	succTr, err := kem.Respond(succKem, succCt, commitment)
	if err != nil {
		t.Fatal(err)
	}
	return kem.BuildPredecessorKEMRecord(fields, predTr, succTr), fields, predSS, succSS
}

// TestKEM_PredecessorPossessionProof: possession of the first (predecessor) KEM key
// is proven by decapsulation of a challenge to the first public key (PCAS-claim-30).
func TestKEM_PredecessorPossessionProof(t *testing.T) {
	rec, _, predSS, succSS := predKEMSetup(t)
	if err := kem.VerifyPredecessorKEM(rec, predSS, succSS); err != nil {
		t.Fatalf("predecessor-KEM verify: %v", err)
	}
	// A wrong predecessor challenger secret fails on the predecessor limb.
	_, wrongSS, err := kem.EncapsulateChallenge(kemAlg, rec.Fields.PredecessorPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := kem.VerifyPredecessorKEM(rec, wrongSS, succSS); err == nil {
		t.Fatal("wrong predecessor secret accepted")
	}
}

// TestKEM_BothTranscriptsBound: both transcripts must be present and bound to the
// SAME commitment; a missing limb or a tampered commitment is rejected (PCAS-claim-30).
func TestKEM_BothTranscriptsBound(t *testing.T) {
	rec, _, predSS, succSS := predKEMSetup(t)

	// Missing a limb.
	missing := kem.PredecessorKEMRecord{Fields: rec.Fields, PredecessorTranscript: rec.PredecessorTranscript}
	if err := kem.VerifyPredecessorKEM(missing, predSS, succSS); !errors.Is(err, kem.ErrMissingTranscripts) {
		t.Fatalf("missing successor transcript: got %v, want ErrMissingTranscripts", err)
	}

	// Tampering the commitment (bound fields) breaks BOTH transcripts.
	tampered := rec
	tampered.Fields.Epoch = 2
	if err := kem.VerifyPredecessorKEM(tampered, predSS, succSS); err == nil {
		t.Fatal("transcripts were not bound to the commitment (tampered commitment accepted)")
	}
}

// --- re-wrap gate (PCAS-claim-15) -----------------------------------------------

type fakeRewrap struct{ complete bool }

func (f *fakeRewrap) RewrapComplete(_, _ string, _ uint64) (bool, error) { return f.complete, nil }

type nopLedger struct{}

func (nopLedger) Append(_ context.Context, e events.Event) (events.Event, error) { return e, nil }

// TestKEMSuccession_RewrapThenRetire: predecessor retirement is blocked until re-wrap
// under the successor completes, then proceeds (PCAS-claim-15 re-wrap-before-retire).
func TestKEMSuccession_RewrapThenRetire(t *testing.T) {
	const tenant, id = "11111111-1111-1111-1111-111111111111", "spiffe://d/id"
	rpKey := ecdsa(t)
	ctrl, err := retirement.New(retirement.Config{
		Roster: retirement.Roster{"rp1": rpKey.Public().DER},
		Policy: retirement.QuorumPolicy{Threshold: 1}, Ledger: nopLedger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := retirement.SignAck(rpKey, tenant, id, 1, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	pred, err := byok.GenerateSigner(context.Background(), nil, tenant, "kem-signing-pred", crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	rw := &fakeRewrap{complete: false}
	mkReq := func() retirement.CutoverRequest {
		return retirement.CutoverRequest{
			Target:      retirement.Target{TenantID: tenant, IdentityID: id, Epoch: 1},
			Acks:        []retirement.SignedAck{{TenantID: tenant, IdentityID: id, Epoch: 1, RelyingParty: "rp1", Signature: sig}},
			Predecessor: pred,
			Successor:   retirement.Successor{Epoch: 2, Algorithm: kemAlg, Class: succession.ClassPurePQ, PublicKeyDER: []byte{1}},
			PreRetire:   kem.RetirementGate(rw, tenant, id, 1),
		}
	}

	// Re-wrap incomplete → retirement blocked, predecessor untouched.
	if _, err := ctrl.Execute(context.Background(), mkReq(), time.Now()); !errors.Is(err, kem.ErrRewrapIncomplete) {
		t.Fatalf("retire before re-wrap: got %v, want ErrRewrapIncomplete", err)
	}
	if pred.State() != byok.StateActive {
		t.Fatalf("predecessor retired before re-wrap completed (state %q)", pred.State())
	}

	// Re-wrap complete → retirement proceeds.
	rw.complete = true
	if _, err := ctrl.Execute(context.Background(), mkReq(), time.Now()); err != nil {
		t.Fatalf("retire after re-wrap: %v", err)
	}
	if pred.State() != byok.StateZeroized {
		t.Fatalf("predecessor not retired after re-wrap (state %q)", pred.State())
	}
}
