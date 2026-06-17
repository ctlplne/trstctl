package crypto

import (
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

func TestSLHDSAGenerateSignVerify(t *testing.T) {
	// Use the "f" (fast-signing) parameter set so the unit test is quick.
	s, err := GenerateSLHDSAKey(SLHDSA128f)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	if s.Algorithm() != SLHDSA128f {
		t.Errorf("algorithm = %q", s.Algorithm())
	}
	msg := []byte("artifact digest to sign")
	sig, err := s.Sign(msg, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := VerifySLHDSA(s.Public(), msg, sig); err != nil {
		t.Fatalf("VerifySLHDSA: %v", err)
	}
	// Wrong message must fail.
	if err := VerifySLHDSA(s.Public(), []byte("tampered"), sig); err == nil {
		t.Error("SLH-DSA verified a wrong message")
	}
	// Wrong key must fail.
	other, err := GenerateSLHDSAKey(SLHDSA128f)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	if err := VerifySLHDSA(other.Public(), msg, sig); err == nil {
		t.Error("SLH-DSA verified against the wrong key")
	}
}

func TestIsSLHDSA(t *testing.T) {
	if !IsSLHDSA(SLHDSA128s) || !IsSLHDSA(SLHDSA256s) {
		t.Error("SLH-DSA parameter sets not recognized")
	}
	if IsSLHDSA(ECDSAP256) || IsSLHDSA("nonsense") {
		t.Error("non-SLH-DSA algorithm misclassified")
	}
}

func TestGenerateSLHDSAKeyZeroizesGeneratedPrivateKey(t *testing.T) {
	var captured *slhdsa.PrivateKey
	prev := slhdsaPrivateKeyObserver
	slhdsaPrivateKeyObserver = func(k *slhdsa.PrivateKey) { captured = k }
	defer func() { slhdsaPrivateKeyObserver = prev }()

	s, err := GenerateSLHDSAKey(SLHDSA128f)
	if err != nil {
		t.Fatalf("GenerateSLHDSAKey: %v", err)
	}
	defer s.Destroy()
	assertSLHDSAPrivateKeyZeroed(t, captured)

	msg := []byte("locked slh-dsa source still signs")
	sig, err := s.Sign(msg, SignOptions{})
	if err != nil {
		t.Fatalf("Sign after generated-key wipe: %v", err)
	}
	if err := VerifySLHDSA(s.Public(), msg, sig); err != nil {
		t.Fatalf("VerifySLHDSA after generated-key wipe: %v", err)
	}
}

func TestSLHDSASignZeroizesParsedPrivateKey(t *testing.T) {
	s, err := GenerateSLHDSAKey(SLHDSA128f)
	if err != nil {
		t.Fatalf("GenerateSLHDSAKey: %v", err)
	}
	defer s.Destroy()

	var captured *slhdsa.PrivateKey
	prev := slhdsaPrivateKeyObserver
	slhdsaPrivateKeyObserver = func(k *slhdsa.PrivateKey) { captured = k }
	defer func() { slhdsaPrivateKeyObserver = prev }()

	msg := []byte("slh-dsa residue test")
	sig, err := s.Sign(msg, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := VerifySLHDSA(s.Public(), msg, sig); err != nil {
		t.Fatalf("VerifySLHDSA: %v", err)
	}
	assertSLHDSAPrivateKeyZeroed(t, captured)
}

func assertSLHDSAPrivateKeyZeroed(t *testing.T, key *slhdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		t.Fatal("observer was not called")
	}
	encoded, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary after wipe: %v", err)
	}
	for i, b := range encoded {
		if b != 0 {
			t.Fatalf("private-key byte %d still live after wipe", i)
		}
	}
}
