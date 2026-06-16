package pqc_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/pqc"
)

func TestSignVerify(t *testing.T) {
	for _, alg := range []crypto.Algorithm{
		crypto.MLDSA44, crypto.MLDSA65, crypto.MLDSA87, crypto.HybridEd25519Dilithium3,
	} {
		signer, err := pqc.GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%v): %v", alg, err)
		}
		if signer.Algorithm() != alg {
			t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), alg)
		}
		if signer.Public().Algorithm != alg || len(signer.Public().DER) == 0 {
			t.Fatalf("bad public key: %+v", signer.Public())
		}
		msg := []byte("post-quantum message to sign")
		sig, err := signer.Sign(msg, crypto.SignOptions{})
		if err != nil {
			t.Fatalf("Sign(%v): %v", alg, err)
		}
		if len(sig) == 0 {
			t.Fatal("empty signature")
		}
		if err := pqc.Verify(signer.Public(), msg, sig); err != nil {
			t.Errorf("Verify(%v) of a valid signature failed: %v", alg, err)
		}
		if err := pqc.Verify(signer.Public(), []byte("tampered"), sig); err == nil {
			t.Errorf("Verify(%v) accepted a tampered message", alg)
		}
		signer.Destroy()
		if _, err := signer.Sign(msg, crypto.SignOptions{}); err == nil {
			t.Errorf("Sign(%v) after Destroy should fail", alg)
		}
	}
}

// TestImplementsBoundaryInterfaces proves a PQC key is a first-class signer
// behind the boundary (interchangeable with classical keys).
func TestImplementsBoundaryInterfaces(t *testing.T) {
	signer, err := pqc.GenerateKey(crypto.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()

	var _ crypto.Signer = signer
	var _ crypto.DigestSigner = signer

	digest := []byte("0123456789abcdef0123456789abcdef")
	sig, err := signer.SignDigest(digest, crypto.SignOptions{})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if err := pqc.Verify(signer.Public(), digest, sig); err != nil {
		t.Errorf("Verify of digest signature failed: %v", err)
	}
}

func TestMLKEMIsNotSignable(t *testing.T) {
	for _, alg := range []crypto.Algorithm{crypto.MLKEM512, crypto.MLKEM768, crypto.MLKEM1024} {
		if _, err := pqc.GenerateKey(alg); err == nil {
			t.Errorf("GenerateKey(%v) should fail: ML-KEM is a KEM, not a signature scheme", alg)
		}
	}
}
