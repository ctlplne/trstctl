// These tests are written from a caller's perspective: the external test
// package imports only the boundary and never a standard-library crypto package
// (which is exactly the AN-3 property the boundary exists to guarantee).
package crypto_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestSignAndVerify(t *testing.T) {
	cases := []struct {
		name string
		alg  crypto.Algorithm
		opts crypto.SignOptions
	}{
		{"RSA2048-PKCS1v15", crypto.RSA2048, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}},
		{"RSA2048-PSS", crypto.RSA2048, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPSS}},
		{"ECDSA-P256", crypto.ECDSAP256, crypto.SignOptions{Hash: crypto.SHA256}},
		{"ECDSA-P384", crypto.ECDSAP384, crypto.SignOptions{Hash: crypto.SHA384}},
		{"ECDSA-P521", crypto.ECDSAP521, crypto.SignOptions{Hash: crypto.SHA512}},
	}
	be := crypto.NewSoftwareBackend()
	msg := []byte("the quick brown fox jumps over the lazy dog")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signer, err := be.GenerateKey(c.alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if signer.Algorithm() != c.alg {
				t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), c.alg)
			}
			sig, err := signer.Sign(msg, c.opts)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("empty signature")
			}
			pub := signer.Public()
			if pub.Algorithm != c.alg || len(pub.DER) == 0 {
				t.Fatalf("bad public key: %+v", pub)
			}
			if err := crypto.Verify(pub, msg, sig, c.opts); err != nil {
				t.Errorf("Verify of a valid signature failed: %v", err)
			}
			if err := crypto.Verify(pub, []byte("tampered"), sig, c.opts); err == nil {
				t.Error("Verify accepted a tampered message")
			}
		})
	}
}

func TestGenerateAllSupportedAlgorithms(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	// RSA-4096 is omitted here only to keep the suite fast; it shares the exact
	// generation path as RSA-2048/3072 (see rsaBits).
	for _, alg := range []crypto.Algorithm{
		crypto.RSA2048, crypto.RSA3072,
		crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521,
	} {
		signer, err := be.GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%v): %v", alg, err)
		}
		if got := signer.Public().Algorithm; got != alg {
			t.Errorf("public key algorithm = %v, want %v", got, alg)
		}
	}
}

func TestGenerateKeyRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := crypto.NewSoftwareBackend().GenerateKey(crypto.Algorithm("bogus")); err == nil {
		t.Error("expected an error for an unknown algorithm")
	}
}

func TestSignRejectsUnsupportedHash(t *testing.T) {
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign([]byte("x"), crypto.SignOptions{Hash: crypto.Hash("MD5")}); err == nil {
		t.Error("expected an error for an unsupported hash")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	opts := crypto.SignOptions{Hash: crypto.SHA256}
	a, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	sig, err := a.Sign(msg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.Verify(b.Public(), msg, sig, opts); err == nil {
		t.Error("Verify accepted a signature under the wrong public key")
	}
}

// --- swappable-backend proof (AN-3 acceptance) ---

// exercise is written purely against the boundary interfaces; it must compile
// and run unchanged for ANY backend.
func exercise(t *testing.T, kg crypto.KeyGenerator, alg crypto.Algorithm) {
	t.Helper()
	signer, err := kg.GenerateKey(alg)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := signer.Sign([]byte("payload"), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	if signer.Public().Algorithm != alg {
		t.Fatalf("algorithm mismatch: %v != %v", signer.Public().Algorithm, alg)
	}
}

func TestBackendsAreSwappable(t *testing.T) {
	// Identical caller code, two different backends, zero changes.
	exercise(t, crypto.NewSoftwareBackend(), crypto.ECDSAP256)
	exercise(t, fakeBackend{}, crypto.ECDSAP256)
}

// fakeBackend is an alternative backend defined entirely against the boundary
// interfaces with no dependency on crypto/* — proving callers and alternative
// backends never need the standard library's crypto packages.
type fakeBackend struct{}

func (fakeBackend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	return &fakeSigner{alg: alg}, nil
}

type fakeSigner struct{ alg crypto.Algorithm }

func (f *fakeSigner) Public() crypto.PublicKey {
	return crypto.PublicKey{Algorithm: f.alg, DER: []byte("fake-spki")}
}
func (f *fakeSigner) Algorithm() crypto.Algorithm { return f.alg }
func (f *fakeSigner) Sign(message []byte, _ crypto.SignOptions) ([]byte, error) {
	return append([]byte("fake-sig:"), message...), nil
}
