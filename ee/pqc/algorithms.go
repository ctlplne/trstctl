// SPDX-License-Identifier: LicenseRef-trstctl-EE

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

	HybridEd25519Dilithium3         crypto.Algorithm = "Hybrid-Ed25519-Dilithium3"
	HybridMLDSA44ECDSAP256Algorithm                  = "Hybrid-ML-DSA-44-ECDSA-P256"
)
