// SPDX-License-Identifier: BUSL-1.1

package pqc

import "trstctl.com/trstctl/internal/crypto"

type Algorithm = crypto.Algorithm
type PublicKey = crypto.PublicKey
type SignOptions = crypto.SignOptions

const (
	MLDSA44 crypto.Algorithm = "ML-DSA-44"
	MLDSA65 crypto.Algorithm = "ML-DSA-65"
	MLDSA87 crypto.Algorithm = "ML-DSA-87"

	MLKEM512  crypto.Algorithm = "ML-KEM-512"
	MLKEM768  crypto.Algorithm = "ML-KEM-768"
	MLKEM1024 crypto.Algorithm = "ML-KEM-1024"

	SLHDSA128s crypto.Algorithm = "SLH-DSA-SHA2-128s"
	SLHDSA128f crypto.Algorithm = "SLH-DSA-SHA2-128f"
	SLHDSA192s crypto.Algorithm = "SLH-DSA-SHA2-192s"
	SLHDSA256s crypto.Algorithm = "SLH-DSA-SHA2-256s"

	HybridEd25519Dilithium3 crypto.Algorithm = "Hybrid-Ed25519-Dilithium3"
)

// HybridMLDSA44ECDSAP256Algorithm is the hybrid TLS algorithm name as it appears
// in migration plans and API payloads, which carry it as a plain string rather
// than a crypto.Algorithm. It sits outside the const group above deliberately:
// it has a different type from every member of that group, and mixing the two
// left it as an untyped constant that silently satisfied both (staticcheck
// SA9004).
const HybridMLDSA44ECDSAP256Algorithm string = "Hybrid-ML-DSA-44-ECDSA-P256"
