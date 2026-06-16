package crypto_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestDigestHelper(t *testing.T) {
	d, err := crypto.Digest(crypto.SHA256, []byte("abc"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if len(d) != 32 {
		t.Errorf("SHA-256 digest len = %d, want 32", len(d))
	}
	if _, err := crypto.Digest(crypto.Hash("MD5"), []byte("x")); err == nil {
		t.Error("expected an error for an unsupported hash")
	}
}

// TestLockedSigner exercises the AN-8 key type: the private key lives as PKCS#8
// DER inside a locked secret buffer and is parsed only for each signature.
func TestLockedSigner(t *testing.T) {
	for _, alg := range []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256} {
		ls, err := crypto.GenerateLockedKey(alg)
		if err != nil {
			t.Fatalf("GenerateLockedKey(%v): %v", alg, err)
		}
		if ls.Algorithm() != alg {
			t.Errorf("Algorithm() = %v, want %v", ls.Algorithm(), alg)
		}
		if ls.Public().Algorithm != alg || len(ls.Public().DER) == 0 {
			t.Fatalf("bad public key: %+v", ls.Public())
		}
		opts := crypto.SignOptions{Hash: crypto.SHA256}
		digest, err := crypto.Digest(crypto.SHA256, []byte("message to sign"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := ls.SignDigest(digest, opts)
		if err != nil {
			t.Fatalf("SignDigest: %v", err)
		}
		if err := crypto.VerifyDigest(ls.Public(), digest, sig, opts); err != nil {
			t.Errorf("VerifyDigest of a valid signature failed: %v", err)
		}
		// Destroy zeroizes the locked key; further use must fail.
		ls.Destroy()
		if _, err := ls.SignDigest(digest, opts); err == nil {
			t.Error("SignDigest after Destroy should fail")
		}
	}
}

// TestCreateAndVerifyCSR is the in-process analogue of the over-UDS CSR test:
// a DigestSigner (here a LockedSigner) signs a CSR through internal/crypto.
func TestCreateAndVerifyCSR(t *testing.T) {
	ls, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ls.Destroy()

	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "test.trstctl.com",
		DNSNames:   []string{"test.trstctl.com"},
	}, ls)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if len(csr) == 0 {
		t.Fatal("empty CSR")
	}
	if err := crypto.VerifyCertificateRequest(csr); err != nil {
		t.Errorf("VerifyCertificateRequest of a valid CSR failed: %v", err)
	}

	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)/2] ^= 0xFF
	if err := crypto.VerifyCertificateRequest(tampered); err == nil {
		t.Error("VerifyCertificateRequest accepted a tampered CSR")
	}
}
