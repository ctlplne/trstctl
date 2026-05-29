package crypto

import "fmt"

// SelectAlgorithm maps a named policy profile to the signing algorithm to use.
// It is the minimal, policy-selectable algorithm choice; the full policy engine
// (OPA) arrives in S8.7. The empty profile is treated as "classical".
func SelectAlgorithm(profile string) (Algorithm, error) {
	switch profile {
	case "", "classical":
		return ECDSAP256, nil
	case "pqc", "post-quantum":
		return MLDSA65, nil
	case "hybrid":
		return HybridEd25519Dilithium3, nil
	default:
		return "", fmt.Errorf("crypto: unknown algorithm policy profile %q", profile)
	}
}
