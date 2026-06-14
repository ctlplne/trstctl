package crypto

import "fmt"

// Classification describes an algorithm for the crypto inventory: its family,
// whether it signs or encapsulates keys, and its quantum-vulnerability status.
// It is the hook the inventory uses to flag which credentials must migrate to
// post-quantum algorithms.
type Classification struct {
	Algorithm         Algorithm
	Family            string // RSA, ECDSA, ML-DSA, ML-KEM, Hybrid
	Kind              string // "signature" or "kem"
	QuantumVulnerable bool   // breakable by a cryptographically-relevant quantum computer
	PostQuantum       bool   // designed to resist quantum attacks
}

// Classify returns the classification of an algorithm, or an error if it is
// unknown.
func Classify(a Algorithm) (Classification, error) {
	switch a {
	case RSA2048, RSA3072, RSA4096:
		return Classification{Algorithm: a, Family: "RSA", Kind: "signature", QuantumVulnerable: true}, nil
	case ECDSAP256, ECDSAP384, ECDSAP521:
		return Classification{Algorithm: a, Family: "ECDSA", Kind: "signature", QuantumVulnerable: true}, nil
	case MLDSA44, MLDSA65, MLDSA87:
		return Classification{Algorithm: a, Family: "ML-DSA", Kind: "signature", PostQuantum: true}, nil
	case SLHDSA128s, SLHDSA128f, SLHDSA192s, SLHDSA256s:
		return Classification{Algorithm: a, Family: "SLH-DSA", Kind: "signature", PostQuantum: true}, nil
	case MLKEM512, MLKEM768, MLKEM1024:
		return Classification{Algorithm: a, Family: "ML-KEM", Kind: "kem", PostQuantum: true}, nil
	case HybridEd25519Dilithium3:
		return Classification{Algorithm: a, Family: "Hybrid", Kind: "signature", PostQuantum: true}, nil
	default:
		return Classification{}, fmt.Errorf("crypto: unknown algorithm %q", a)
	}
}
