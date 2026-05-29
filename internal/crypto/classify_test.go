package crypto_test

import (
	"testing"

	"certctl.io/certctl/internal/crypto"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		alg         crypto.Algorithm
		vulnerable  bool
		postQuantum bool
		family      string
		kind        string
	}{
		{crypto.RSA2048, true, false, "RSA", "signature"},
		{crypto.RSA4096, true, false, "RSA", "signature"},
		{crypto.ECDSAP256, true, false, "ECDSA", "signature"},
		{crypto.ECDSAP521, true, false, "ECDSA", "signature"},
		{crypto.MLDSA44, false, true, "ML-DSA", "signature"},
		{crypto.MLDSA65, false, true, "ML-DSA", "signature"},
		{crypto.MLDSA87, false, true, "ML-DSA", "signature"},
		{crypto.MLKEM512, false, true, "ML-KEM", "kem"},
		{crypto.MLKEM768, false, true, "ML-KEM", "kem"},
		{crypto.MLKEM1024, false, true, "ML-KEM", "kem"},
		{crypto.HybridEd25519Dilithium3, false, true, "Hybrid", "signature"},
	}
	for _, c := range cases {
		got, err := crypto.Classify(c.alg)
		if err != nil {
			t.Fatalf("Classify(%v): %v", c.alg, err)
		}
		if got.Algorithm != c.alg ||
			got.QuantumVulnerable != c.vulnerable ||
			got.PostQuantum != c.postQuantum ||
			got.Family != c.family ||
			got.Kind != c.kind {
			t.Errorf("Classify(%v) = %+v; want vuln=%v pq=%v family=%q kind=%q",
				c.alg, got, c.vulnerable, c.postQuantum, c.family, c.kind)
		}
	}
	if _, err := crypto.Classify(crypto.Algorithm("bogus")); err == nil {
		t.Error("Classify of an unknown algorithm should error")
	}
}

func TestSelectAlgorithm(t *testing.T) {
	cases := map[string]crypto.Algorithm{
		"classical": crypto.ECDSAP256,
		"":          crypto.ECDSAP256,
		"pqc":       crypto.MLDSA65,
		"hybrid":    crypto.HybridEd25519Dilithium3,
	}
	for profile, want := range cases {
		got, err := crypto.SelectAlgorithm(profile)
		if err != nil || got != want {
			t.Errorf("SelectAlgorithm(%q) = %v, %v; want %v", profile, got, err, want)
		}
	}
	if _, err := crypto.SelectAlgorithm("nonsense"); err == nil {
		t.Error("SelectAlgorithm of an unknown profile should error")
	}
}
