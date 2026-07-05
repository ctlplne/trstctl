// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import "trstctl.com/trstctl/internal/crypto"

// StrengthClass is a coarse cryptographic-strength class. The signer enforces a
// partial order over classes — PurePQ >= Hybrid >= Classical — and refuses a
// forward succession to a strictly weaker class absent a break-glass
// authorization (claim 17 / INV-8). The order is signer configuration, never
// request input, so a compromised control plane cannot redefine "weaker".
type StrengthClass int

const (
	ClassUnknownStrength StrengthClass = iota
	StrengthClassical
	StrengthHybrid
	StrengthPurePQ
)

// classByAlg maps registry algorithm identifiers to their strength class.
var classByAlg = map[crypto.Algorithm]StrengthClass{
	crypto.RSA2048:   StrengthClassical,
	crypto.RSA3072:   StrengthClassical,
	crypto.RSA4096:   StrengthClassical,
	crypto.ECDSAP256: StrengthClassical,
	crypto.ECDSAP384: StrengthClassical,
	crypto.ECDSAP521: StrengthClassical,
	crypto.Ed25519:   StrengthClassical,

	crypto.Algorithm("ML-DSA-44"):    StrengthPurePQ,
	crypto.Algorithm("ML-DSA-65"):    StrengthPurePQ,
	crypto.Algorithm("ML-DSA-87"):    StrengthPurePQ,
	crypto.Algorithm("SLH-DSA-128s"): StrengthPurePQ,
	crypto.Algorithm("SLH-DSA-128f"): StrengthPurePQ,
	crypto.Algorithm("SLH-DSA-192s"): StrengthPurePQ,
	crypto.Algorithm("SLH-DSA-256s"): StrengthPurePQ,

	crypto.Algorithm("Ed25519+ML-DSA-65"):    StrengthHybrid,
	crypto.Algorithm("ECDSA-P256+ML-DSA-65"): StrengthHybrid,
}

// ClassOf returns the strength class of alg (ClassUnknownStrength if unregistered).
func ClassOf(alg crypto.Algorithm) StrengthClass { return classByAlg[alg] }

// IsStrengthDowngrade reports whether succ is a strictly weaker class than pred.
// Unknown classes never register as a downgrade (the caller enforces registry
// membership elsewhere).
func IsStrengthDowngrade(pred, succ crypto.Algorithm) bool {
	pc, sc := classByAlg[pred], classByAlg[succ]
	if pc == ClassUnknownStrength || sc == ClassUnknownStrength {
		return false
	}
	return sc < pc
}
