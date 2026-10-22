// SPDX-License-Identifier: BUSL-1.1

package crypto

// HashNone asks a DigestSigner to sign the supplied bytes as the whole
// message, with no pre-hash. Only a pure-message signature family accepts it
// (ML-DSA and SLH-DSA sign the message directly under FIPS 204/205); an RFC
// 9881 certificate, CRL or OCSP signature covers the full TBS bytes, so the
// signer process has to see them. Classical keys refuse HashNone.
const HashNone Hash = "none"

// PureMessageSignatureAlgorithm reports whether alg signs a message directly
// rather than a digest of it, so HashNone is meaningful for it.
func PureMessageSignatureAlgorithm(alg Algorithm) bool {
	switch alg {
	case Algorithm("ML-DSA-44"), Algorithm("ML-DSA-65"), Algorithm("ML-DSA-87"),
		Algorithm("SLH-DSA-SHA2-128s"), Algorithm("SLH-DSA-SHA2-128f"),
		Algorithm("SLH-DSA-SHA2-192s"), Algorithm("SLH-DSA-SHA2-256s"):
		return true
	default:
		return false
	}
}
