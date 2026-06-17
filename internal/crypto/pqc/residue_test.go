package pqc

import (
	"testing"

	"github.com/cloudflare/circl/sign"

	core "trstctl.com/trstctl/internal/crypto"
)

func TestGenerateKeyZeroizesGeneratedCIRCLPrivateKey(t *testing.T) {
	for _, alg := range []core.Algorithm{core.MLDSA44, core.HybridEd25519Dilithium3} {
		t.Run(string(alg), func(t *testing.T) {
			var captured sign.PrivateKey
			prev := generatePrivateKeyObserver
			generatePrivateKeyObserver = func(k sign.PrivateKey) { captured = k }
			defer func() { generatePrivateKeyObserver = prev }()

			signer, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			defer signer.Destroy()
			assertCIRCLPrivateKeyZeroed(t, captured)

			msg := []byte("locked source still signs")
			sig, err := signer.Sign(msg, core.SignOptions{})
			if err != nil {
				t.Fatalf("Sign after generated-key wipe: %v", err)
			}
			if err := Verify(signer.Public(), msg, sig); err != nil {
				t.Fatalf("Verify after generated-key wipe: %v", err)
			}
		})
	}
}

func TestSignZeroizesParsedCIRCLPrivateKey(t *testing.T) {
	for _, alg := range []core.Algorithm{core.MLDSA44, core.HybridEd25519Dilithium3} {
		t.Run(string(alg), func(t *testing.T) {
			signer, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			defer signer.Destroy()

			var captured sign.PrivateKey
			prev := signPrivateKeyObserver
			signPrivateKeyObserver = func(k sign.PrivateKey) { captured = k }
			defer func() { signPrivateKeyObserver = prev }()

			msg := []byte("post-quantum residue test")
			sig, err := signer.Sign(msg, core.SignOptions{})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if err := Verify(signer.Public(), msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			assertCIRCLPrivateKeyZeroed(t, captured)
		})
	}
}

func assertCIRCLPrivateKeyZeroed(t *testing.T, key sign.PrivateKey) {
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
