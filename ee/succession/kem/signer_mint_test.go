// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kem_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/kem"
	"trstctl.com/trstctl/internal/crypto"
)

// signerCustody stands in for the signer's key custody: it generates the paired signing
// key and the ML-KEM successor INSIDE itself and retains both private keys, exposing
// only public material — mirroring the real signer boundary (INT-12).
type signerCustody struct {
	be         crypto.Backend
	pairedPriv crypto.Signer        // retained; only the Signer view is handed out
	kemPriv    *eepqc.KEMPrivateKey // retained; NEVER exported
	kemPubDER  []byte
}

func (c *signerCustody) GeneratePairedSigningKey(string) (crypto.Signer, error) {
	k, err := c.be.GenerateKey(crypto.ECDSAP384)
	if err != nil {
		return nil, err
	}
	c.pairedPriv = k
	return k, nil
}

func (c *signerCustody) GenerateKEMSuccessor(_, kemAlg string) ([]byte, error) {
	k, err := eepqc.GenerateKEMKey(crypto.Algorithm(kemAlg))
	if err != nil {
		return nil, err
	}
	c.kemPriv = k
	c.kemPubDER = k.Public().DER
	return c.kemPubDER, nil
}

// TestINT12_KEMSuccessionThroughSigner mints a Variant-B KEM succession through the
// signer custody boundary: the KEM successor key is generated inside the signer and
// only its PUBLIC key crosses out, the record is publicly verifiable, and the re-wrap
// retirement gate blocks predecessor retirement until re-wrap completion is recorded
// (claim 15, INT-12).
func TestINT12_KEMSuccessionThroughSigner(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	custody := &signerCustody{be: be}

	fields := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/kem", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	rec, err := kem.MintPairedThroughSigner(fields, pred, custody, "paired-1", "kem-1", string(eepqc.MLKEM768))
	if err != nil {
		t.Fatalf("mint KEM through signer: %v", err)
	}

	// The record is publicly verifiable offline (base dual-attestation + KEM binding).
	if err := kem.VerifyPaired(rec); err != nil {
		t.Fatalf("paired KEM record failed verify: %v", err)
	}
	if rec.KEMAlg != string(eepqc.MLKEM768) || len(rec.KEMPub) == 0 {
		t.Fatalf("record missing KEM public material: %+v", rec.KEMAlg)
	}

	// Custody discipline (INT-INV-2): only the KEM PUBLIC key crossed out. The KEM
	// private key is retained in the signer and is not the public key.
	if custody.kemPriv == nil {
		t.Fatal("signer did not retain the KEM private key")
	}
	privBytes, err := custody.kemPriv.PrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rec.KEMPub, privBytes) {
		t.Fatal("record carries KEM private bytes; the private key must never leave the signer")
	}
	if !bytes.Equal(rec.KEMPub, custody.kemPubDER) {
		t.Fatal("record KEM public key does not match the signer-generated key")
	}

	// Re-wrap-before-retire gate: retirement is blocked until re-wrap completes.
	led := &rewrapLedger{}
	gate := kem.RetirementGate(led, "t", "spiffe://d/kem", 0)
	if err := gate(context.Background()); !errors.Is(err, kem.ErrRewrapIncomplete) {
		t.Fatalf("gate before re-wrap: got %v, want ErrRewrapIncomplete", err)
	}
	led.done = true
	if err := gate(context.Background()); err != nil {
		t.Fatalf("gate after re-wrap completion: %v", err)
	}
}

type rewrapLedger struct{ done bool }

func (l *rewrapLedger) RewrapComplete(string, string, uint64) (bool, error) { return l.done, nil }
