// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// eMudhra, Part 4: a post-quantum CA key proves possession through the same
// challenge as a classical one (the signer signs the challenge's SHA-256
// digest bytes), and a key reporting another's public half fails. The
// weak-key checks have no classical structure to test and pass it.
func TestCeremonyPossessionCoversPostQuantumKeys(t *testing.T) {
	ml, err := GenerateKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ml.Destroy)
	hybrid, err := GenerateKey(HybridEd25519Dilithium3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hybrid.Destroy)
	slh, err := GenerateSLHDSAKey(SLHDSA128f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(slh.Destroy)
	for name, key := range map[string]crypto.DigestSigner{"ML-DSA-65": ml, "Ed25519-Dilithium3": hybrid, "SLH-DSA-SHA2-128f": slh} {
		if err := crypto.ProvePossession(key, key.Public()); err != nil {
			t.Fatalf("%s holder: %v", name, err)
		}
		if err := crypto.RefuseWeakKey(key.Public()); err != nil {
			t.Fatalf("%s weak-key check: %v", name, err)
		}
	}
	other, err := GenerateKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Destroy)
	if err := crypto.ProvePossession(ml, other.Public()); err == nil {
		t.Fatal("an ML-DSA key proved possession of another key")
	}
}
