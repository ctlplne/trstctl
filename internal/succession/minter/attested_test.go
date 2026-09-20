// SPDX-License-Identifier: BUSL-1.1

package minter_test

import (
	"bytes"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rpverify"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/attest"
	"trstctl.com/trstctl/internal/succession/minter"
)

func algClassKey(a crypto.Algorithm) string {
	switch a {
	case crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521, crypto.RSA2048, crypto.RSA3072, crypto.RSA4096, crypto.Ed25519:
		return "classical"
	default:
		return "pqc"
	}
}

// attVerifier confirms the evidence's declared class (a real verifier checks the quote
// against local roots); an injected error models a failing/foreign attestation.
type attVerifier struct{ err error }

func (v attVerifier) Verify(e attest.Evidence) (attest.Class, error) {
	if v.err != nil {
		return attest.ClassNone, v.err
	}
	return attest.ClassOfType(e.Type), nil
}

func evidenceBytes(t *testing.T, typ string) []byte {
	t.Helper()
	b, err := attest.Encode(attest.Evidence{Type: typ, Blob: []byte("quote:" + typ)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func attestedMinter(t *testing.T, minByClass map[string]attest.Class, verr error) (*minter.Minter, *countingKeygen, map[string][]byte) {
	t.Helper()
	ck := &countingKeygen{inner: crypto.NewSoftwareBackend()}
	pred, _ := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	attestKey, _ := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	gate := attest.Gate{Verifier: attVerifier{err: verr}, MinByClass: minByClass, AlgClass: algClassKey}
	m, err := minter.New(mapResolver{"pred": pred}, ck, newMemFloor(),
		minter.WithAttestationGate(gate), minter.WithAttestation(attestKey, "signer-1"))
	if err != nil {
		t.Fatal(err)
	}
	return m, ck, map[string][]byte{"signer-1": attestKey.Public().DER}
}

// TestAttested_VerifyBeforeGenerate: attestation is verified before keygen — a valid
// attestation mints (keygen once); an absent or failing attestation prevents keygen
// entirely (PCAS-claim-35 / INV-15).
func TestAttested_VerifyBeforeGenerate(t *testing.T) {
	// classical gated at ClassSoftware; software evidence meets it.
	m, ck, _ := attestedMinter(t, map[string]attest.Class{"classical": attest.ClassSoftware}, nil)
	req := baseReq()
	req.Attestation = evidenceBytes(t, "software")
	if _, err := m.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("valid attestation mint: %v", err)
	}
	if ck.n != 1 {
		t.Fatalf("keygen ran %d times, want 1", ck.n)
	}

	// Absent attestation → refused before keygen.
	m2, ck2, _ := attestedMinter(t, map[string]attest.Class{"classical": attest.ClassSoftware}, nil)
	if _, err := m2.MintSuccessor(ctx, baseReq()); err == nil {
		t.Fatal("mint with no attestation succeeded")
	}
	if ck2.n != 0 {
		t.Fatalf("keygen ran %d times on absent attestation, want 0", ck2.n)
	}

	// Failing attestation (verifier rejects) → refused before keygen.
	m3, ck3, _ := attestedMinter(t, map[string]attest.Class{"classical": attest.ClassSoftware}, errors.New("foreign custodian"))
	req3 := baseReq()
	req3.Attestation = evidenceBytes(t, "software")
	if _, err := m3.MintSuccessor(ctx, req3); err == nil {
		t.Fatal("mint with a failing attestation succeeded")
	}
	if ck3.n != 0 {
		t.Fatalf("keygen ran %d times on failing attestation, want 0", ck3.n)
	}
}

// TestAttested_EvidenceDigestBound: the evidence digest + type are bound in the record
// (by the signer attestation) and verifiable from the published evidence (PCAS-claim-35).
func TestAttested_EvidenceDigestBound(t *testing.T) {
	m, _, roster := attestedMinter(t, map[string]attest.Class{"classical": attest.ClassSoftware}, nil)
	ev := attest.Evidence{Type: "software", Blob: []byte("quote:software")}
	evBytes, _ := attest.Encode(ev)
	req := baseReq()
	req.Attestation = evBytes
	res, err := m.MintSuccessor(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := minter.DecodeRecord(res.EncodedRecord)

	if !bytes.Equal(rec.AttestationEvidenceDigest, attest.Digest(ev)) || rec.AttestationType != "software" {
		t.Fatal("record does not bind the evidence digest + type")
	}
	// Bound by the signer attestation: altering the type breaks it.
	tampered := rec
	tampered.AttestationType = "hsm"
	if _, err := succession.VerifyAttestation(roster, tampered); err == nil {
		t.Fatal("attestation type/class is not bound by the signer attestation (spoofable)")
	}
	// Verifiable from the published evidence.
	if err := rpverify.VerifyEvidenceDigest(rec, ev); err != nil {
		t.Fatalf("evidence digest verify: %v", err)
	}
	if rpverify.VerifyEvidenceDigest(rec, attest.Evidence{Type: "software", Blob: []byte("different")}) == nil {
		t.Fatal("evidence digest matched a different custodian's evidence")
	}
}

// TestAttested_MinClassGate: a gated algorithm class refuses below-minimum evidence at
// mint, and the relying party rejects such a record; un-gated classes are unaffected
// (PCAS-claim-35; RP mirror).
func TestAttested_MinClassGate(t *testing.T) {
	// classical gated at ClassHardwareTPM; software evidence is below minimum → refused.
	m, ck, _ := attestedMinter(t, map[string]attest.Class{"classical": attest.ClassHardwareTPM}, nil)
	below := baseReq()
	below.Attestation = evidenceBytes(t, "software")
	if _, err := m.MintSuccessor(ctx, below); err == nil {
		t.Fatal("below-minimum-class evidence minted")
	}
	if ck.n != 0 {
		t.Fatalf("keygen ran on below-min evidence (%d), want 0", ck.n)
	}

	// hardware-tpm evidence meets the minimum → mints.
	m2, _, roster := attestedMinter(t, map[string]attest.Class{"classical": attest.ClassHardwareTPM}, nil)
	ok := baseReq()
	ok.Attestation = evidenceBytes(t, "hardware-tpm")
	res, err := m2.MintSuccessor(ctx, ok)
	if err != nil {
		t.Fatalf("hardware-tpm mint: %v", err)
	}
	rec, _ := minter.DecodeRecord(res.EncodedRecord)

	// RP mirror: a policy at the same minimum accepts it.
	accept := rpverify.AttestedPolicy{SignerRoster: roster, MinByClass: map[string]attest.Class{"classical": attest.ClassHardwareTPM}, AlgClass: algClassKey}
	if err := rpverify.VerifyAttestedRecord(rec, accept); err != nil {
		t.Fatalf("RP mirror rejected a sufficient-class record: %v", err)
	}
	// RP mirror rejects when it requires a higher class than the record carries.
	strict := rpverify.AttestedPolicy{SignerRoster: roster, MinByClass: map[string]attest.Class{"classical": attest.ClassHSM}, AlgClass: algClassKey}
	if err := rpverify.VerifyAttestedRecord(rec, strict); !errors.Is(err, rpverify.ErrAttestationBelowMin) {
		t.Fatalf("RP mirror accepted below-min record: %v", err)
	}

	// Un-gated class unaffected: an ordinary record (no attestation) passes an
	// attested policy that does not gate its class.
	plain, _, _ := setup(t)
	plainRes, err := plain.MintSuccessor(ctx, baseReq())
	if err != nil {
		t.Fatal(err)
	}
	plainRec, _ := minter.DecodeRecord(plainRes.EncodedRecord)
	unGated := rpverify.AttestedPolicy{MinByClass: map[string]attest.Class{"pqc": attest.ClassHSM}, AlgClass: algClassKey}
	if err := rpverify.VerifyAttestedRecord(plainRec, unGated); err != nil {
		t.Fatalf("un-gated (classical) ordinary record was affected: %v", err)
	}
}
