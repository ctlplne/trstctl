// SPDX-License-Identifier: BUSL-1.1

package monitor_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/monitor"
	"trstctl.com/trstctl/internal/translog"
)

type int19Ledger struct{ evs []events.Event }

func (l *int19Ledger) Append(_ context.Context, e events.Event) (events.Event, error) {
	l.evs = append(l.evs, e)
	return e, nil
}

// attested builds a valid dual-signed record for identity at epoch, countersigned by
// the attestation signer (naming signerID). Distinct successor keys make two records at
// the same epoch equivocate.
func attested(t *testing.T, identity string, epoch uint64, attest crypto.Signer, signerID string) succession.SuccessionRecord {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	pred, _ := be.GenerateKey(crypto.ECDSAP256)
	succ, _ := be.GenerateKey(crypto.ECDSAP384)
	fields := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: identity, TenantID: "t",
		PredecessorEpoch: epoch - 1, Epoch: epoch,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	commitment, _ := succession.Commit(fields)
	predSig, _ := pred.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	succSig, _ := succ.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	rec := succession.SuccessionRecord{
		Fields: fields, PredecessorAtt: predSig,
		Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
	}
	att, err := succession.Attest(attest, signerID, rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.SignerAttestation = att
	return rec
}

// TestINT19_MisissuanceMonitorDetectsAndEmits drives the misissuance monitor over a
// record stream: it detects the first algorithm-epoch equivocation, emits a durable
// misissuance event that decodes to a self-verifying artifact naming the minting
// signers, and changes nothing on a clean stream (PCAS-claims-11, 28).
func TestINT19_MisissuanceMonitorDetectsAndEmits(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	signerA, _ := be.GenerateKey(crypto.ECDSAP256)
	signerB, _ := be.GenerateKey(crypto.ECDSAP256)
	roster := map[string][]byte{"signer-A": signerA.Public().DER, "signer-B": signerB.Public().DER}

	ledger := &int19Ledger{}
	m := monitor.New(roster, ledger)

	// A stream with a non-colliding record, then two DISTINCT records for one identity
	// at the SAME epoch (an equivocation).
	clean := attested(t, "spiffe://d/other", 1, signerA, "signer-A")
	a := attested(t, "spiffe://d/id", 1, signerA, "signer-A")
	b := attested(t, "spiffe://d/id", 1, signerB, "signer-B")

	det, ok, err := m.Scan(context.Background(), []succession.SuccessionRecord{clean, a, b})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !ok {
		t.Fatal("monitor did not detect the equivocation")
	}
	// The detection is a self-verifying proof naming both minting signers.
	if err := translog.VerifyMisissuanceProof(det.Proof); err != nil {
		t.Fatalf("emitted proof does not verify: %v", err)
	}
	if det.SignerA != "signer-A" || det.SignerB != "signer-B" {
		t.Fatalf("named signers = %q,%q; want signer-A,signer-B", det.SignerA, det.SignerB)
	}
	// A durable, decodable misissuance event landed on the ledger.
	if len(ledger.evs) != 1 {
		t.Fatalf("emitted %d events, want 1", len(ledger.evs))
	}
	payload, err := succession.Decode(ledger.evs[0])
	if err != nil {
		t.Fatalf("decode emitted event: %v", err)
	}
	mis, isMis := payload.(succession.MisissuanceV1)
	if !isMis {
		t.Fatalf("emitted event is %T, want MisissuanceV1", payload)
	}
	if mis.IdentityID != "spiffe://d/id" || mis.Epoch != 1 {
		t.Fatalf("misissuance binds %s@%d, want spiffe://d/id@1", mis.IdentityID, mis.Epoch)
	}
	if mis.SignerA != "signer-A" || mis.SignerB != "signer-B" {
		t.Fatalf("misissuance names %q,%q, want signer-A,signer-B", mis.SignerA, mis.SignerB)
	}
	da, _ := succession.Commit(a.Fields)
	db, _ := succession.Commit(b.Fields)
	if string(mis.RecordADigest) != string(da) || string(mis.RecordBDigest) != string(db) {
		t.Fatal("misissuance event does not bind both record commitments")
	}

	// A clean stream (distinct identities / epochs) triggers nothing.
	clean2 := &int19Ledger{}
	m2 := monitor.New(roster, clean2)
	_, ok, err = m2.Scan(context.Background(), []succession.SuccessionRecord{
		attested(t, "spiffe://d/x", 1, signerA, "signer-A"),
		attested(t, "spiffe://d/x", 2, signerA, "signer-A"),
		attested(t, "spiffe://d/y", 1, signerB, "signer-B"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("monitor reported misissuance on a clean stream")
	}
	if len(clean2.evs) != 0 {
		t.Fatal("monitor emitted an event on a clean stream")
	}

	// A duplicate (identical) record at the same epoch is NOT an equivocation.
	dup := &int19Ledger{}
	m3 := monitor.New(roster, dup)
	same := attested(t, "spiffe://d/z", 1, signerA, "signer-A")
	if _, ok, _ := m3.Scan(context.Background(), []succession.SuccessionRecord{same, same}); ok {
		t.Fatal("monitor treated a duplicate record as an equivocation")
	}
}
