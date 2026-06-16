package crypto_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestSoftwareBackendConforms(t *testing.T) {
	algs := []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256, crypto.ECDSAP384}
	if err := crypto.ConformBackend(crypto.NewSoftwareBackend(), algs); err != nil {
		t.Fatalf("software backend must pass its own conformance harness: %v", err)
	}
}

// s9BrokenBackend returns a signer whose signatures never verify, proving the harness
// actually catches a non-conforming backend (no vacuous pass).
type s9BrokenBackend struct{}

func (s9BrokenBackend) Name() string { return "broken" }
func (s9BrokenBackend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	s, err := crypto.NewSoftwareBackend().GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	return s9CorruptSigner{s}, nil
}

type s9CorruptSigner struct{ crypto.Signer }

func (c s9CorruptSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	sig, err := c.Signer.Sign(message, opts)
	if err != nil {
		return nil, err
	}
	sig[0] ^= 0xff // corrupt the signature so it cannot verify
	return sig, nil
}

func TestConformBackendCatchesBadSigner(t *testing.T) {
	if err := crypto.ConformBackend(s9BrokenBackend{}, []crypto.Algorithm{crypto.ECDSAP256}); err == nil {
		t.Fatal("ConformBackend passed a backend whose signatures do not verify")
	}
}
