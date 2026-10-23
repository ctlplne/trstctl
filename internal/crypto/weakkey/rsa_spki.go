// SPDX-License-Identifier: BUSL-1.1

package weakkey

import (
	"crypto/rsa"
	"crypto/x509"
)

// MaxRSAModulusBits bounds an RSA key the inventory accepts for rating and
// for batch GCD; a larger modulus is not a real deployment.
const MaxRSAModulusBits = 16384

// RSASubjectPublicKeyInfo returns the DER SubjectPublicKeyInfo of an RSA key,
// given a DER certificate (its raw SubjectPublicKeyInfo, the bytes the
// inventory's spki_sha256 hashes) or a DER SubjectPublicKeyInfo. Another key
// type, unparseable input or a modulus over MaxRSAModulusBits gives false.
// The result is public key material, safe to report and store.
func RSASubjectPublicKeyInfo(der []byte) ([]byte, bool) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() > MaxRSAModulusBits {
			return nil, false
		}
		return append([]byte(nil), der...), true
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	k, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || k.N.BitLen() > MaxRSAModulusBits {
		return nil, false
	}
	return append([]byte(nil), cert.RawSubjectPublicKeyInfo...), true
}
