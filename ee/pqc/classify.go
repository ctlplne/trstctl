// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import "trstctl.com/trstctl/internal/crypto"

// ClassifyAlgorithm is the licensed algorithm classifier installed through
// crypto.InstallLicensedAlgorithmClassifier by the tagged attach seam when
// FeaturePQC is licensed. It makes the post-quantum and hybrid labels
// first-class citizens of every surface that classifies through the crypto
// boundary — most importantly certificate-profile `allowed_key_algorithms`
// validation, which previously failed closed on these labels even with the
// license present.
//
// Enforcement semantics stay exact-match: a profile listing "ML-DSA-65"
// admits pure ML-DSA-65 CSRs (whose inspected KeyAlgorithm is exactly that
// label). A hybrid enrollment carries a classical subject key plus the bound
// post-quantum component, so its inspected KeyAlgorithm remains the classical
// family and it is governed by the classical label; the hybrid labels
// classify here so they can be named in policy and inventory without
// tripping authoring validation.
func ClassifyAlgorithm(a crypto.Algorithm) (crypto.Classification, bool) {
	switch a {
	case MLDSA44, MLDSA65, MLDSA87:
		return crypto.Classification{Algorithm: a, Family: "ML-DSA", Kind: "signature", PostQuantum: true}, true
	case MLKEM512, MLKEM768, MLKEM1024:
		return crypto.Classification{Algorithm: a, Family: "ML-KEM", Kind: "kem", PostQuantum: true}, true
	case SLHDSA128s, SLHDSA128f, SLHDSA192s, SLHDSA256s:
		return crypto.Classification{Algorithm: a, Family: "SLH-DSA", Kind: "signature", PostQuantum: true}, true
	case HybridEd25519Dilithium3, crypto.Algorithm(HybridMLDSA44ECDSAP256Algorithm):
		return crypto.Classification{Algorithm: a, Family: "Hybrid", Kind: "signature", PostQuantum: true}, true
	default:
		return crypto.Classification{}, false
	}
}
